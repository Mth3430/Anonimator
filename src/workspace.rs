//! Accès au projet : ce qui peut sortir, confinement des chemins et modifications en attente.

use crate::anon::{secret_report, Anonymizer};
use crate::keep::is_public;
use crate::lexer::{lang_for_extension, Lang};
use crate::scan::{collect_definitions, collect_names_deep, collect_public_imports};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};

const MAX_FILE_BYTES: u64 = 1_000_000;

pub enum FileClass {
    Code(Lang),
    /// Texte libre (Markdown, HTML…) : le lexer ne sait pas y isoler le contenu métier.
    Prose,
    /// Secrets : ne sortent jamais, quel que soit le réglage.
    Forbidden,
}

pub fn classify(relative: &str) -> FileClass {
    let name = relative
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let forbidden_name = name.starts_with(".env")
        || name.starts_with("id_rsa")
        || name.starts_with("id_ed25519")
        || name.starts_with("credentials")
        || name.contains("secret")
        || matches!(name.as_str(), ".npmrc" | ".pypirc" | ".netrc");
    let ext = name.rsplit_once('.').map_or("", |(_, ext)| ext);
    let forbidden_ext = matches!(
        ext,
        "pem" | "key" | "p12" | "pfx" | "jks" | "kdbx" | "keystore"
    );
    let in_git = relative
        .split(['/', '\\'])
        .any(|s| s.eq_ignore_ascii_case(".git"));
    if forbidden_name || forbidden_ext || in_git {
        return FileClass::Forbidden;
    }
    match lang_for_extension(ext) {
        Some(lang) => FileClass::Code(lang),
        None => FileClass::Prose,
    }
}

pub struct Workspace {
    pub root: PathBuf,
    /// Modifications de l'IA, vues comme appliquées par elle, mais pas encore écrites sur le disque.
    pub pending: BTreeMap<String, String>,
    pub allow_prose: bool,
    /// Mode auto : cherche aussi les noms que le projet ne déclare pas.
    pub auto_detect: bool,
}

/// Une modification à faire valider.
#[derive(Clone, Debug)]
pub struct Change {
    pub path: String,
    pub before: String,
    pub after: String,
}

impl Workspace {
    pub fn open(root: &Path, allow_prose: bool) -> Result<Self> {
        let root = root
            .canonicalize()
            .context("dossier du projet introuvable")?;
        Ok(Workspace {
            root,
            pending: BTreeMap::new(),
            allow_prose,
            auto_detect: true,
        })
    }

    /// Chemins relatifs des fichiers visibles (`.gitignore` et fichiers cachés exclus), triés.
    pub fn files(&self) -> Vec<String> {
        let mut out: Vec<String> = ignore::WalkBuilder::new(&self.root)
            .require_git(false)
            .build()
            .flatten()
            .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
            .filter_map(|entry| {
                let relative = entry.path().strip_prefix(&self.root).ok()?;
                Some(relative.to_string_lossy().replace('\\', "/"))
            })
            .collect();
        out.extend(self.pending.keys().cloned());
        out.sort();
        out.dedup();
        out
    }

    /// Fichiers que l'IA en ligne a le droit de connaître.
    pub fn shareable_files(&self) -> Vec<String> {
        self.files()
            .into_iter()
            .filter(|path| match classify(path) {
                FileClass::Code(_) => true,
                FileClass::Prose => self.allow_prose,
                FileClass::Forbidden => false,
            })
            .collect()
    }

    /// Prépare l'anonymiseur : noms déclarés dans le code et noms qui identifient le projet.
    pub fn prepare(&self, anon: &mut Anonymizer) {
        let mut vocab = HashSet::new();
        let mut deny: Vec<String> = Vec::new();
        if let Some(folder) = self.root.file_name() {
            deny.push(folder.to_string_lossy().into_owned());
        }
        if let Some(user) = std::env::var_os("USERNAME").or_else(|| std::env::var_os("USER")) {
            deny.push(user.to_string_lossy().into_owned());
        }
        let mut project_roots = HashSet::new();
        let mut sources = Vec::new();
        for path in self.files() {
            for segment in path.split('/') {
                let stem = segment.split('.').next().unwrap_or("");
                project_roots.insert(stem.to_string());
                if stem.is_empty() || is_public(stem) {
                    continue;
                }
                if stem.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    vocab.insert(stem.to_string());
                } else {
                    deny.push(stem.to_string());
                }
            }
            let FileClass::Code(lang) = classify(&path) else {
                continue;
            };
            let Ok(content) = self.read_real(&path) else {
                continue;
            };
            if self.auto_detect {
                collect_names_deep(&content, &lang, &mut vocab);
            } else {
                collect_definitions(&content, &lang, &mut vocab);
            }
            deny.extend(manifest_name(&path, &content));
            sources.push((lang, content));
        }
        // Le nom du dossier et du paquet désignent aussi le projet dans ses propres imports.
        project_roots.extend(deny.iter().map(|term| term.replace('-', "_")));
        let mut public = HashSet::new();
        for (lang, content) in &sources {
            collect_public_imports(content, lang, &project_roots, &mut public);
        }
        vocab.retain(|name| !public.contains(name));
        anon.set_vocabulary(vocab);
        anon.add_deny_terms(&deny, false);
    }

    /// Emplacements des secrets détectés, `chemin:ligne (type)`, sans leur valeur.
    pub fn secrets_found(&self) -> Vec<String> {
        let mut found = Vec::new();
        for path in self.shareable_files() {
            let FileClass::Code(lang) = classify(&path) else {
                continue;
            };
            let Ok(content) = self.read_real(&path) else {
                continue;
            };
            for (line, label) in secret_report(&content, &lang) {
                found.push(format!("{path}:{line} ({label})"));
            }
        }
        found
    }

    /// Contenu réel, en tenant compte des modifications en attente.
    pub fn read_real(&self, relative: &str) -> Result<String> {
        if let Some(content) = self.pending.get(relative) {
            return Ok(content.clone());
        }
        let path = self.resolve(relative)?;
        let meta = std::fs::metadata(&path).with_context(|| format!("{relative} introuvable"))?;
        if meta.len() > MAX_FILE_BYTES {
            bail!("{relative} dépasse la taille maximale de 1 Mo");
        }
        std::fs::read_to_string(&path)
            .with_context(|| format!("{relative} n'est pas un fichier texte"))
    }

    /// Version anonymisée d'un fichier, seule forme sous laquelle il peut sortir.
    pub fn read_anonymized(&self, relative: &str, anon: &mut Anonymizer) -> Result<String> {
        match classify(relative) {
            FileClass::Forbidden => bail!("accès refusé : fichier sensible"),
            FileClass::Prose if !self.allow_prose => {
                bail!("accès refusé : ce type de fichier n'est pas partagé")
            }
            FileClass::Prose => Ok(anon.prose(&self.read_real(relative)?)),
            FileClass::Code(lang) => anon.code(&self.read_real(relative)?, &lang),
        }
    }

    /// Enregistre une écriture de l'IA, sans toucher au disque.
    pub fn stage(&mut self, relative: &str, content: String) -> Result<()> {
        if matches!(classify(relative), FileClass::Forbidden) {
            bail!("écriture refusée : fichier sensible");
        }
        self.resolve(relative)?;
        self.pending.insert(relative.to_string(), content);
        Ok(())
    }

    pub fn changes(&self) -> Vec<Change> {
        self.pending
            .iter()
            .map(|(path, after)| Change {
                path: path.clone(),
                before: self
                    .resolve(path)
                    .ok()
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .unwrap_or_default(),
                after: after.clone(),
            })
            .collect()
    }

    /// Écrit sur le disque les modifications validées et renvoie leur nombre.
    pub fn apply(&mut self) -> Result<usize> {
        let count = self.pending.len();
        for (relative, content) in &self.pending {
            let path = self.resolve(relative)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, content).with_context(|| format!("écriture de {relative}"))?;
        }
        self.pending.clear();
        Ok(count)
    }

    /// Résout un chemin demandé par l'IA, sans jamais sortir de la racine, liens compris.
    pub fn resolve(&self, relative: &str) -> Result<PathBuf> {
        let candidate = Path::new(relative);
        let confined = candidate
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if relative.is_empty() || !confined {
            bail!("chemin refusé : {relative}");
        }
        let full = self.root.join(candidate);
        let mut existing = full.as_path();
        while !existing.exists() {
            existing = existing
                .parent()
                .ok_or_else(|| anyhow!("chemin refusé : {relative}"))?;
        }
        if !existing.canonicalize()?.starts_with(&self.root) {
            bail!("chemin refusé : {relative} sort du projet");
        }
        Ok(full)
    }
}

/// Nom du paquet déclaré dans un manifeste connu.
fn manifest_name(path: &str, content: &str) -> Option<String> {
    let file = path.rsplit('/').next()?;
    match file {
        "package.json" | "composer.json" => {
            let value: serde_json::Value = serde_json::from_str(content).ok()?;
            value["name"].as_str().map(str::to_string)
        }
        "Cargo.toml" | "pyproject.toml" => content.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "name").then(|| value.trim().trim_matches('"').to_string())
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    fn project() -> (tempfile::TempDir, Workspace) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/billing.rs"), "pub fn charge_customer() {}\n").unwrap();
        std::fs::write(root.join("README.md"), "Projet confidentiel\n").unwrap();
        std::fs::write(root.join(".env"), "TOKEN=abc\n").unwrap();
        std::fs::write(root.join("server.pem"), "clé\n").unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"acme-pay\"\n").unwrap();
        let ws = Workspace::open(root, false).unwrap();
        (dir, ws)
    }

    #[test]
    fn secrets_and_prose_are_not_shared_by_default() {
        let (_dir, ws) = project();
        let files = ws.shareable_files();
        assert!(files.contains(&"src/billing.rs".to_string()));
        assert!(!files
            .iter()
            .any(|f| f.contains("README") || f.contains(".env") || f.contains(".pem")));
        let mut a = Anonymizer::new(Vault::default());
        assert!(ws.read_anonymized(".env", &mut a).is_err());
        assert!(ws.read_anonymized("server.pem", &mut a).is_err());
        assert!(ws.read_anonymized("README.md", &mut a).is_err());
    }

    #[test]
    fn prepare_collects_names_from_code_paths_and_manifest() {
        let (_dir, ws) = project();
        let mut a = Anonymizer::new(Vault::default());
        ws.prepare(&mut a);
        let out = ws.read_anonymized("src/billing.rs", &mut a).unwrap();
        assert!(!out.contains("charge_customer"));
        assert!(a.deny_terms().iter().any(|t| t == "acme-pay"));
        assert!(!a.path("src/billing.rs").contains("billing"));
    }

    #[test]
    fn traversal_and_absolute_paths_are_refused() {
        let (_dir, mut ws) = project();
        for bad in [
            "../outside.rs",
            "src/../../outside.rs",
            "C:\\Windows\\x.rs",
            "/etc/passwd",
            "",
        ] {
            assert!(ws.resolve(bad).is_err(), "{bad}");
            assert!(ws.stage(bad, String::new()).is_err(), "{bad}");
        }
        assert!(ws.stage(".env", "x".into()).is_err());
        assert!(ws.stage(".git/hooks/pre-commit", "x".into()).is_err());
    }

    #[test]
    fn stage_is_visible_but_only_apply_touches_disk() {
        let (dir, mut ws) = project();
        ws.stage("src/new/thing.rs", "fn a() {}".into()).unwrap();
        assert_eq!(ws.read_real("src/new/thing.rs").unwrap(), "fn a() {}");
        assert!(!dir.path().join("src/new/thing.rs").exists());
        assert_eq!(ws.changes().len(), 1);
        assert_eq!(ws.apply().unwrap(), 1);
        assert!(dir.path().join("src/new/thing.rs").exists());
        assert!(ws.pending.is_empty());
    }
}
