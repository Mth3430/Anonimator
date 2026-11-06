//! Coffre des correspondances entre valeurs réelles et pseudonymes aléatoires.
//! Il ne quitte jamais la machine et les pseudonymes ne dérivent pas des valeurs.

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const SUFFIX_LEN: usize = 6;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Class {
    Ident,
    Str,
    Comment,
    Pii,
}

/// Motif de tous les pseudonymes, sans frontière de mot : l'IA peut en faire
/// un morceau d'un nouveau nom, comme `get_zq_abc123`.
pub fn token_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:zq_|zs_|zc_|zp_|Zq)[a-z0-9]{6}|ZQ_[A-Z0-9]{6}").expect("regex valide")
    })
}

#[derive(Default, Serialize, Deserialize)]
pub struct Vault {
    /// pseudonyme -> valeur réelle
    reverse: HashMap<String, String>,
    #[serde(skip)]
    forward: HashMap<(u8, String), String>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl Vault {
    pub fn load(path: &Path) -> Result<Self> {
        let mut vault = if path.exists() {
            let raw = std::fs::read_to_string(path).context("lecture du coffre")?;
            serde_json::from_str::<Vault>(&raw).context("coffre illisible")?
        } else {
            Vault::default()
        };
        vault.forward = vault
            .reverse
            .iter()
            .map(|(token, value)| ((class_of(token) as u8, value.clone()), token.clone()))
            .collect();
        vault.path = Some(path.to_path_buf());
        Ok(vault)
    }

    pub fn save(&self) -> Result<()> {
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, serde_json::to_vec(self)?).context("écriture du coffre")?;
        }
        Ok(())
    }

    pub fn token(&mut self, class: Class, value: &str) -> String {
        let key = (class as u8, value.to_string());
        if let Some(existing) = self.forward.get(&key) {
            return existing.clone();
        }
        let token = loop {
            let candidate = new_token(class, value);
            if !self.reverse.contains_key(&candidate) {
                break candidate;
            }
        };
        self.reverse.insert(token.clone(), value.to_string());
        self.forward.insert(key, token.clone());
        token
    }

    pub fn lookup(&self, token: &str) -> Option<&str> {
        self.reverse.get(token).map(String::as_str)
    }

    /// Remplace chaque pseudonyme connu par sa valeur, en une seule passe.
    pub fn restore(&self, text: &str) -> String {
        token_regex()
            .replace_all(text, |caps: &regex::Captures| {
                let found = &caps[0];
                self.lookup(found).unwrap_or(found).to_string()
            })
            .into_owned()
    }

    /// Paires (pseudonyme, valeur) triées, pour l'affichage.
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut all: Vec<_> = self
            .reverse
            .iter()
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect();
        all.sort();
        all
    }

    pub fn len(&self) -> usize {
        self.reverse.len()
    }

    pub fn is_empty(&self) -> bool {
        self.reverse.is_empty()
    }
}

fn class_of(token: &str) -> Class {
    match token.get(..3) {
        Some("zs_") => Class::Str,
        Some("zc_") => Class::Comment,
        Some("zp_") => Class::Pii,
        _ => Class::Ident,
    }
}

fn new_token(class: Class, value: &str) -> String {
    match class {
        Class::Str => format!("zs_{}", random_suffix(LOWER)),
        Class::Comment => format!("zc_{}", random_suffix(LOWER)),
        Class::Pii => format!("zp_{}", random_suffix(LOWER)),
        Class::Ident => {
            let has_lower = value.chars().any(char::is_lowercase);
            let first_upper = value.chars().next().is_some_and(char::is_uppercase);
            if !has_lower && first_upper {
                format!("ZQ_{}", random_suffix(UPPER))
            } else if first_upper {
                format!("Zq{}", random_suffix(LOWER))
            } else {
                format!("zq_{}", random_suffix(LOWER))
            }
        }
    }
}

fn random_suffix(alphabet: &[u8]) -> String {
    let mut bytes = [0u8; SUFFIX_LEN];
    getrandom::getrandom(&mut bytes).expect("aléa système indisponible");
    bytes
        .iter()
        .map(|b| alphabet[*b as usize % alphabet.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_value_same_token_and_naming_style_kept() {
        let mut v = Vault::default();
        let a = v.token(Class::Ident, "invoice_total");
        assert_eq!(a, v.token(Class::Ident, "invoice_total"));
        assert!(a.starts_with("zq_"));
        assert!(v.token(Class::Ident, "InvoiceTotal").starts_with("Zq"));
        assert!(v.token(Class::Ident, "MAX_RETRY").starts_with("ZQ_"));
    }

    #[test]
    fn restore_handles_tokens_inside_new_names_and_ignores_unknown() {
        let mut v = Vault::default();
        let t = v.token(Class::Ident, "invoice");
        let text = format!("get_{t}_v2 zq_zzzzzz");
        assert_eq!(v.restore(&text), "get_invoice_v2 zq_zzzzzz");
    }

    #[test]
    fn restore_does_not_expand_recursively() {
        let mut v = Vault::default();
        let inner = v.token(Class::Ident, "secret_name");
        let outer = v.token(Class::Str, &inner); // la valeur ressemble à un pseudonyme
        assert_eq!(v.restore(&outer), inner);
    }

    #[test]
    fn persists_and_reloads_with_same_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("vault.json");
        let mut v = Vault::load(&path).unwrap();
        let t = v.token(Class::Comment, "note interne");
        v.save().unwrap();
        let mut again = Vault::load(&path).unwrap();
        assert_eq!(again.lookup(&t), Some("note interne"));
        assert_eq!(again.token(Class::Comment, "note interne"), t);
    }
}
