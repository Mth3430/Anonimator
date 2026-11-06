//! Moteur d'anonymisation : code, texte libre, chemins, restauration et audit de sortie.

use crate::keep::is_public;
use crate::lexer::{lex, Kind, Lang, Token};
use crate::vault::{token_regex, Class, Vault};
use anyhow::{bail, Result};
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;
use std::sync::OnceLock;

/// Longueur minimale d'un terme interdit, car il est aussi cherché à l'intérieur des mots.
const MIN_TERM_LEN: usize = 3;

fn pii_patterns() -> &'static [(&'static str, Regex)] {
    static RE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    RE.get_or_init(|| {
        [
            (
                "clé privée",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
            ),
            ("clé d'API", r"\bsk-[A-Za-z0-9_-]{16,}"),
            ("clé Stripe", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{10,}"),
            ("clé Google", r"\bAIza[0-9A-Za-z_-]{30,}"),
            ("clé AWS", r"\bAKIA[0-9A-Z]{16}\b"),
            ("jeton GitHub", r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
            ("jeton Slack", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
            (
                "JWT",
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            ),
            ("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}\b"),
            ("carte bancaire", r"\b(?:\d{4}[ -]){3}\d{4}\b"),
            (
                "téléphone",
                r"\+\d{1,3}[ .-]?\d(?:[ .-]?\d){7,12}\b|\b0[1-9](?:[ .-]\d{2}){4}\b|\b0[67]\d{8}\b",
            ),
            (
                "e-mail",
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}",
            ),
            ("URL", r#"\b[a-z][a-z0-9+.-]*://[^\s"'<>)\]]+"#),
            ("adresse IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            ("chemin Windows", r#"\b[A-Za-z]:\\[^\s"'<>|]+"#),
            ("chemin personnel", r#"/(?:home|Users)/[^\s"'<>|]+"#),
        ]
        .into_iter()
        .map(|(label, pattern)| (label, Regex::new(pattern).expect("regex valide")))
        .collect()
    })
}

/// Nom qui annonce un secret : la valeur qui suit est masquée quelle que soit sa forme.
fn sensitive_name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)passw|passphrase|pwd|mdp|motdepasse|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization|auth[_-]?key|bearer|cookie|jwt|salt|(?:^|_)pin(?:$|_)",
        )
        .expect("regex valide")
    })
}

/// « mot de passe : abc » dans un message : seule la valeur (groupe 1) est masquée.
fn prose_secret_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:password|passwd|pwd|secret|token|api[ _-]?key|mot de passe|mdp|cl[ée])\s*(?:est|is|:|=)\s*(\S+)")
            .expect("regex valide")
    })
}

fn version_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d+\.\d+(?:\.\d+)?$").expect("regex valide"))
}

/// Long, mêlant lettres et chiffres, et peu répétitif : ressemble à une clé générée.
fn looks_generated(text: &str) -> bool {
    let shape = text.len() >= 20
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c))
        && text.chars().any(|c| c.is_ascii_digit())
        && text.chars().any(|c| c.is_ascii_alphabetic());
    if !shape {
        return false;
    }
    let mut counts = [0u32; 256];
    for byte in text.bytes() {
        counts[byte as usize] += 1;
    }
    let total = text.len() as f64;
    let entropy: f64 = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = f64::from(*count) / total;
            -p * p.log2()
        })
        .sum();
    entropy >= 3.5
}

/// Indices des tokens à masquer d'office : valeur d'un nom sensible ou clé générée.
fn forced_tokens(tokens: &[Token]) -> HashSet<usize> {
    let mut forced = HashSet::new();
    for (index, token) in tokens.iter().enumerate() {
        match token.kind {
            Kind::Ident | Kind::Number if looks_generated(token.text) => {
                forced.insert(index);
            }
            _ => {}
        }
        let name = match token.kind {
            Kind::Ident => token.text,
            Kind::Str => &token.text[token.body.0..token.body.1],
            _ => continue,
        };
        if !sensitive_name_regex().is_match(name) {
            continue;
        }
        let mut assigned = false;
        for (offset, next) in tokens[index + 1..].iter().enumerate().take(24) {
            match next.kind {
                Kind::Space if next.text.contains('\n') => break,
                Kind::Space | Kind::Comment => {}
                Kind::Punct if matches!(next.text, "=" | ":") => assigned = true,
                // `headers['Authorization'] = …` : le crochet précède l'affectation.
                Kind::Punct if !assigned && matches!(next.text, "]" | ")") => {}
                Kind::Punct if !assigned || matches!(next.text, ";" | ",") => break,
                Kind::Str | Kind::Number if assigned => {
                    forced.insert(index + 1 + offset);
                    break;
                }
                _ => {}
            }
        }
    }
    forced
}

/// Secrets et données personnelles d'un fichier, sans leur valeur : (ligne, libellé).
pub fn secret_report(src: &str, lang: &Lang) -> Vec<(usize, &'static str)> {
    let tokens = lex(src, lang);
    let forced = forced_tokens(&tokens);
    let mut found = Vec::new();
    let line_of = |offset: usize| src[..offset].matches('\n').count() + 1;
    let mut offset = 0;
    for (index, token) in tokens.iter().enumerate() {
        if forced.contains(&index) {
            found.push((line_of(offset), "mot de passe ou clé"));
        }
        offset += token.text.len();
    }
    for (label, re) in pii_patterns() {
        if matches!(
            *label,
            "URL" | "adresse IP" | "chemin Windows" | "chemin personnel"
        ) {
            continue;
        }
        found.extend(re.find_iter(src).map(|m| (line_of(m.start()), *label)));
    }
    found.sort();
    found.dedup();
    found
}

fn word_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[\p{L}_][\p{L}\p{N}_]*").expect("regex valide"))
}

pub struct Anonymizer {
    pub vault: Vault,
    vocab: HashSet<String>,
    deny: Vec<String>,
    deny_re: Option<Regex>,
}

impl Anonymizer {
    pub fn new(vault: Vault) -> Self {
        Anonymizer {
            vault,
            vocab: HashSet::new(),
            deny: Vec::new(),
            deny_re: None,
        }
    }

    pub fn set_vocabulary(&mut self, vocab: HashSet<String>) {
        self.vocab = vocab;
    }

    pub fn vocabulary_len(&self) -> usize {
        self.vocab.len()
    }

    pub fn deny_terms(&self) -> &[String] {
        &self.deny
    }

    /// Ajoute des termes interdits. Ceux qui sont trop courts ou génériques sont ignorés,
    /// sauf `forced` : un terme choisi par l'utilisateur est toujours appliqué s'il est assez long.
    pub fn add_deny_terms<S: AsRef<str>>(&mut self, terms: &[S], forced: bool) {
        for term in terms {
            let term = term.as_ref().trim();
            let too_generic = !forced && is_public(term);
            if term.chars().count() < MIN_TERM_LEN || too_generic {
                continue;
            }
            if !self.deny.iter().any(|t| t.eq_ignore_ascii_case(term)) {
                self.deny.push(term.to_string());
            }
        }
        self.rebuild_deny_regex();
    }

    fn rebuild_deny_regex(&mut self) {
        let mut sorted: Vec<&String> = self.deny.iter().collect();
        sorted.sort_by_key(|t| std::cmp::Reverse(t.len()));
        let alternatives: Vec<String> = sorted.iter().map(|t| regex::escape(t)).collect();
        self.deny_re = (!alternatives.is_empty()).then(|| {
            RegexBuilder::new(&alternatives.join("|"))
                .case_insensitive(true)
                .build()
                .expect("termes échappés")
        });
    }

    fn is_denied(&self, text: &str) -> bool {
        self.deny_re.as_ref().is_some_and(|re| re.is_match(text))
    }

    /// Anonymise du code. Refuse s'il n'est pas restituable à l'identique : rien de
    /// douteux ne doit partir, et rien ne doit revenir abîmé.
    pub fn code(&mut self, src: &str, lang: &Lang) -> Result<String> {
        let mut out = String::with_capacity(src.len());
        let tokens = lex(src, lang);
        let forced = forced_tokens(&tokens);
        let mut significant: Vec<&str> = Vec::new();
        // Fichier de données : après `:` ou `=`, un mot sans guillemets est une valeur.
        let mut in_data_value = false;
        for (index, token) in tokens.iter().enumerate() {
            let is_forced = forced.contains(&index);
            match token.kind {
                Kind::Ident => {
                    let data_value = in_data_value && !is_public(token.text);
                    if is_forced
                        || data_value
                        || self.vocab.contains(token.text)
                        || self.is_denied(token.text)
                    {
                        out.push_str(&self.vault.token(Class::Ident, token.text));
                    } else {
                        out.push_str(token.text);
                    }
                }
                Kind::Number if is_forced => {
                    out.push_str(&self.vault.token(Class::Str, token.text))
                }
                Kind::Str => {
                    let body = &token.text[token.body.0..token.body.1];
                    if body.is_empty()
                        || (!is_forced && self.string_stays_visible(body, &significant))
                    {
                        out.push_str(token.text);
                    } else {
                        out.push_str(&token.text[..token.body.0]);
                        out.push_str(&self.vault.token(Class::Str, body));
                        out.push_str(&token.text[token.body.1..]);
                    }
                }
                Kind::Comment => {
                    let body = &token.text[token.body.0..token.body.1];
                    if body.chars().any(char::is_alphanumeric) {
                        let trimmed = body.trim_start();
                        let lead = body.len() - trimmed.len();
                        out.push_str(&token.text[..token.body.0 + lead]);
                        out.push_str(&self.vault.token(Class::Comment, trimmed));
                        out.push_str(&token.text[token.body.1..]);
                    } else {
                        out.push_str(token.text);
                    }
                }
                Kind::Space | Kind::Punct | Kind::Number => out.push_str(token.text),
            }
            if !matches!(token.kind, Kind::Space | Kind::Comment) {
                significant.push(token.text);
            }
            if lang.data_only {
                if token.kind == Kind::Space && token.text.contains('\n') {
                    in_data_value = false;
                } else if token.kind == Kind::Punct && matches!(token.text, ":" | "=") {
                    in_data_value = true;
                }
            }
        }
        let out = self.scrub_pii(&out);
        if self.vault.restore(&out) != src {
            bail!("ce fichier ne peut pas être anonymisé de façon réversible");
        }
        Ok(out)
    }

    fn string_stays_visible(&self, body: &str, significant: &[&str]) -> bool {
        let names_project = word_regex()
            .find_iter(body)
            .any(|w| self.vocab.contains(w.as_str()));
        if self.is_denied(body) || names_project {
            return false;
        }
        if !body.chars().any(char::is_alphabetic) {
            // Séparateurs, formats et versions restent lisibles, mais pas `"123456"`.
            let digits = body.chars().filter(|c| c.is_ascii_digit()).count();
            return digits < 4 || version_regex().is_match(body);
        }
        body.chars().count() < MIN_TERM_LEN || self.is_public_import(body, significant)
    }

    /// Un paquet public peut rester lisible, contrairement à un import relatif,
    /// à un hôte privé ou à un segment qui correspond à un nom du projet.
    fn is_public_import(&self, body: &str, significant: &[&str]) -> bool {
        let last = significant.last().copied().unwrap_or("");
        let in_import = matches!(last, "from" | "import")
            || (last == "("
                && significant.len() >= 2
                && significant[significant.len() - 2] == "require");
        if !in_import || body.starts_with('.') || body.starts_with('/') {
            return false;
        }
        let shape_ok = body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@-_./".contains(c));
        let first = body.split('/').next().unwrap_or("");
        shape_ok
            && !first.contains('.')
            && body
                .split(['/', '-', '_', '.', '@'])
                .all(|segment| !self.vocab.contains(segment))
    }

    /// Anonymise du texte libre : secrets et données personnelles, termes interdits, noms du projet.
    pub fn prose(&mut self, text: &str) -> String {
        let mut unmasked = String::with_capacity(text.len());
        let mut last = 0;
        for caps in prose_secret_regex().captures_iter(text) {
            let value = caps.get(1).expect("groupe obligatoire");
            unmasked.push_str(&text[last..value.start()]);
            unmasked.push_str(&self.vault.token(Class::Pii, value.as_str()));
            last = value.end();
        }
        unmasked.push_str(&text[last..]);
        let scrubbed = self.scrub_pii(&unmasked);
        let denied = match self.deny_re.clone() {
            Some(re) => self.map_outside_tokens(&scrubbed, &re),
            None => scrubbed,
        };
        let vocab = std::mem::take(&mut self.vocab);
        let result = map_gaps(&denied, |gap, out| {
            let mut last = 0;
            for found in word_regex().find_iter(gap) {
                out.push_str(&gap[last..found.start()]);
                if vocab.contains(found.as_str()) {
                    out.push_str(&self.vault.token(Class::Ident, found.as_str()));
                } else {
                    out.push_str(found.as_str());
                }
                last = found.end();
            }
            out.push_str(&gap[last..]);
        });
        self.vocab = vocab;
        result
    }

    fn map_outside_tokens(&mut self, text: &str, re: &Regex) -> String {
        map_gaps(text, |gap, out| {
            let mut last = 0;
            for found in re.find_iter(gap) {
                out.push_str(&gap[last..found.start()]);
                out.push_str(&self.vault.token(Class::Ident, found.as_str()));
                last = found.end();
            }
            out.push_str(&gap[last..]);
        })
    }

    fn scrub_pii(&mut self, text: &str) -> String {
        let mut current = text.to_string();
        for (_, re) in pii_patterns() {
            if re.is_match(&current) {
                current = map_gaps(&current, |gap, out| {
                    let mut last = 0;
                    for found in re.find_iter(gap) {
                        out.push_str(&gap[last..found.start()]);
                        out.push_str(&self.vault.token(Class::Pii, found.as_str()));
                        last = found.end();
                    }
                    out.push_str(&gap[last..]);
                });
            }
        }
        current
    }

    /// Pseudonymise un chemin relatif segment par segment, en gardant `/` et les extensions.
    pub fn path(&mut self, relative: &str) -> String {
        relative
            .split(['/', '\\'])
            .map(|segment| {
                let (stem, rest) = match segment.find('.') {
                    Some(0) | None => (segment, ""),
                    Some(dot) => segment.split_at(dot),
                };
                let keep = is_public(stem) || segment.starts_with('.');
                if keep && !self.is_denied(stem) {
                    format!("{stem}{rest}")
                } else {
                    format!("{}{rest}", self.vault.token(Class::Ident, stem))
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    pub fn restore(&self, text: &str) -> String {
        self.vault.restore(text)
    }

    /// Dernière barrière avant l'envoi : renvoie ce qui ne devrait pas se trouver dans `text`.
    /// Le résultat doit être vide, sinon l'envoi est bloqué.
    pub fn audit(&self, text: &str) -> Vec<String> {
        let mut findings = Vec::new();
        for_each_gap(text, |gap| {
            for (label, re) in pii_patterns() {
                if let Some(found) = re.find(gap) {
                    findings.push(format!("{label} : {}", found.as_str()));
                }
            }
            if let Some(found) = self.deny_re.as_ref().and_then(|re| re.find(gap)) {
                findings.push(format!("terme interdit : {}", found.as_str()));
            }
            for found in word_regex().find_iter(gap) {
                if self.vocab.contains(found.as_str()) {
                    findings.push(format!("nom du projet : {}", found.as_str()));
                }
            }
        });
        findings.sort();
        findings.dedup();
        findings
    }
}

/// Reconstruit `text` en gardant les pseudonymes et en passant le reste à `f`.
fn map_gaps(text: &str, mut f: impl FnMut(&str, &mut String)) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for found in token_regex().find_iter(text) {
        f(&text[last..found.start()], &mut out);
        out.push_str(found.as_str());
        last = found.end();
    }
    f(&text[last..], &mut out);
    out
}

fn for_each_gap(text: &str, mut f: impl FnMut(&str)) {
    let mut last = 0;
    for found in token_regex().find_iter(text) {
        f(&text[last..found.start()]);
        last = found.end();
    }
    f(&text[last..]);
}

/// Pseudonymes restés dans un texte déjà restauré : l'IA en a abîmé la forme.
pub fn leftover_tokens(text: &str) -> Vec<String> {
    let mut found: Vec<String> = token_regex()
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lang_for_extension;
    use crate::scan::collect_definitions;

    const RUST: &str = r#"// Facturation interne ACME : ne pas diffuser
use crate::billing::Invoice;
pub struct AcmeClient { api_secret: String }
/// Calcule la marge de Jean Dupont
pub fn compute_margin(gross_amount: f32) -> f32 {
    let admin_mail = "jean.dupont@acme-corp.fr";
    let hidden_key = "sk-abcdefghijklmnop1234";
    println!("{}", admin_mail);
    gross_amount * 0.42
}
"#;

    fn engine(src: &str, ext: &str, deny: &[&str]) -> Anonymizer {
        let mut vocab = HashSet::new();
        collect_definitions(src, &lang_for_extension(ext).unwrap(), &mut vocab);
        let mut a = Anonymizer::new(Vault::default());
        a.set_vocabulary(vocab);
        a.add_deny_terms(deny, true);
        a
    }

    #[test]
    fn code_round_trips_and_hides_everything_sensitive() {
        let lang = lang_for_extension("rs").unwrap();
        let mut a = engine(RUST, "rs", &["ACME", "billing"]);
        let out = a.code(RUST, &lang).unwrap();
        for secret in [
            "ACME",
            "Acme",
            "acme",
            "Facturation",
            "Jean",
            "Dupont",
            "dupont",
            "sk-abc",
            "compute_margin",
            "gross_amount",
            "api_secret",
            "admin_mail",
            "hidden_key",
            "billing",
            "0.42x",
        ] {
            assert!(!out.contains(secret), "{secret} a fuité dans :\n{out}");
        }
        for public in ["println", "String", "f32", "pub fn", "\"{}\""] {
            assert!(out.contains(public), "{public} a disparu de :\n{out}");
        }
        assert_eq!(a.restore(&out), RUST);
        assert_eq!(a.audit(&out), Vec::<String>::new());
    }

    fn masks_all(ext: &str, src: &str, secrets: &[&str]) {
        let lang = lang_for_extension(ext).unwrap();
        let mut a = engine("", ext, &[]);
        let out = a.code(src, &lang).unwrap();
        for secret in secrets {
            assert!(!out.contains(secret), "{secret} a fuité dans :\n{out}");
        }
        assert_eq!(a.restore(&out), src);
        assert!(a.audit(&out).is_empty(), "{out}");
    }

    #[test]
    fn secrets_are_found_without_any_keyword_from_the_user() {
        masks_all(
            "py",
            "db_password = \"123456\"\npin = 4821\nDB_PWD='x1'\n",
            &["123456", "4821", "x1"],
        );
        masks_all(
            "ts",
            "const cfg = { apiKey: \"ab\", token: 987654 };\nheaders['Authorization'] = 'zz';\n",
            &["\"ab\"", "987654", "'zz'"],
        );
        masks_all(
            "rs",
            "let auth_token: &str = \"ab\";\nlet salt = 77;\n",
            &["\"ab\"", " 77"],
        );
        masks_all(
            "yaml",
            "database:\n  host: db.interne.corp\n  password: hunter2\n  pin: 1234\n",
            &["hunter2", "1234", "interne", "corp"],
        );
        masks_all("toml", "[db]\npassword = 'ab'\n", &["'ab'"]);
        masks_all(
            "json",
            "{\"secret\": \"ab\", \"pin\": 4821}",
            &["\"ab\"", "4821"],
        );
        masks_all(
            "py",
            "x = 'aGVsbG8gd29ybGQgdGhpcyBpcyBsb25n1234'\nh = a1b2c3d4e5f60718293a4b5c6d7e8f90\n",
            &["aGVsbG8", "a1b2c3d4"],
        );
        // Découpée pour ne pas ressembler à une vraie clé aux yeux des scanners de dépôts.
        let fake_stripe = format!(
            "s = 'sk_{}_abcdefghijkl1234'\nt = '06 12 34 56 78'\nn = '123456789'\n",
            "live"
        );
        masks_all("py", &fake_stripe, &["sk_live", "06 12", "123456789"]);
    }

    #[test]
    fn ordinary_code_is_not_mistaken_for_a_secret() {
        let lang = lang_for_extension("rs").unwrap();
        let mut a = engine("", "rs", &[]);
        let src = "let port = 8080;\nlet ratio = 0.5;\nlet v = \"1.2.3\";\nprintln!(\"{}: {}\", a, b);\nlet t = get_token(3);\n";
        let out = a.code(src, &lang).unwrap();
        for visible in ["8080", "0.5", "\"1.2.3\"", "\"{}: {}\"", "get_token(3)"] {
            assert!(out.contains(visible), "{visible} a disparu :\n{out}");
        }
        assert!(secret_report(src, &lang).is_empty());
    }

    #[test]
    fn dependency_tables_stay_readable() {
        let lang = lang_for_extension("toml").unwrap();
        let mut a = engine("", "toml", &[]);
        let out = a
            .code(
                "[dependencies]\nserde = \"1\"\nureq = { version = \"2.1\" }\n",
                &lang,
            )
            .unwrap();
        assert!(
            out.contains("serde = \"1\"") && out.contains("ureq = { version = \"2.1\" }"),
            "{out}"
        );
    }

    #[test]
    fn secret_report_gives_lines_without_values() {
        let lang = lang_for_extension("py").unwrap();
        let report = secret_report("a = 1\npassword = 'hunter2'\nmail = 'a@b.fr'\n", &lang);
        assert_eq!(report, vec![(2, "mot de passe ou clé"), (3, "e-mail")]);
    }

    #[test]
    fn secrets_in_a_message_are_masked() {
        let mut a = engine("", "rs", &[]);
        let text = "Connecte-toi, le mot de passe : hunter2 et mdp=abc123 merci";
        let out = a.prose(text);
        assert!(!out.contains("hunter2") && !out.contains("abc123"), "{out}");
        assert_eq!(a.restore(&out), text);
    }

    #[test]
    fn same_name_gets_same_token_across_files() {
        let lang = lang_for_extension("rs").unwrap();
        let mut a = engine("fn shared_helper() {}", "rs", &[]);
        let one = a.code("fn shared_helper() {}", &lang).unwrap();
        let two = a.code("shared_helper();", &lang).unwrap();
        let token = token_regex().find(&one).unwrap().as_str().to_string();
        assert!(two.contains(&token));
    }

    #[test]
    fn deny_term_inside_identifier_masks_whole_identifier() {
        let lang = lang_for_extension("py").unwrap();
        let mut a = engine("", "py", &["acme"]);
        let out = a.code("x = get_ACME_client()", &lang).unwrap();
        assert!(!out.to_lowercase().contains("acme"));
        assert_eq!(a.restore(&out), "x = get_ACME_client()");
    }

    #[test]
    fn imports_public_stay_private_are_masked() {
        let lang = lang_for_extension("ts").unwrap();
        let src = "import React from 'react';\nimport { x } from './internal/secretThing';\n\
                   import y from 'github.com/acme/y';\nconst label = 'Bonjour Madame';\n";
        let mut a = engine(src, "ts", &[]);
        let out = a.code(src, &lang).unwrap();
        assert!(out.contains("'react'"));
        assert!(!out.contains("secretThing"));
        assert!(!out.contains("acme"));
        assert!(!out.contains("Bonjour"));
        assert_eq!(a.restore(&out), src);
    }

    #[test]
    fn prose_masks_pii_terms_and_vocabulary() {
        let mut a = engine("fn compute_margin() {}", "rs", &["Acme Corp"]);
        let text = "Pour acme corp, corrige compute_margin. Contact : a.b@acme.fr, serveur 10.1.2.3, https://intranet.local/x, C:\\Users\\jean\\p";
        let out = a.prose(text);
        for secret in [
            "acme corp",
            "compute_margin",
            "a.b@",
            "10.1.2.3",
            "intranet",
            "jean",
        ] {
            assert!(!out.contains(secret), "{secret} a fuité dans : {out}");
        }
        assert!(out.contains("corrige"));
        assert_eq!(a.restore(&out), text);
        assert!(a.audit(&out).is_empty());
    }

    #[test]
    fn deny_term_never_corrupts_existing_tokens() {
        let mut a = engine("", "rs", &["abc"]);
        // Plusieurs passages, avec des pseudonymes pouvant contenir "abc".
        for _ in 0..200 {
            let once = a.prose("abc et encore abc");
            let twice = a.prose(&once);
            assert_eq!(a.restore(&twice), "abc et encore abc");
        }
    }

    #[test]
    fn audit_detects_leaks_when_text_was_not_anonymized() {
        let a = engine("fn compute_margin() {}", "rs", &["acme"]);
        let found = a.audit("compute_margin acme a@b.fr");
        assert_eq!(found.len(), 3, "{found:?}");
    }

    #[test]
    fn paths_keep_extension_and_generic_folders() {
        let mut a = engine("", "rs", &[]);
        let out = a.path("src\\billing\\invoice.test.rs");
        assert!(out.starts_with("src/zq_"));
        assert!(out.ends_with(".test.rs"));
        assert!(!out.contains("billing") && !out.contains("invoice"));
        assert_eq!(a.restore(&out), "src/billing/invoice.test.rs");
    }

    #[test]
    fn file_already_containing_a_token_is_refused_rather_than_damaged() {
        let lang = lang_for_extension("rs").unwrap();
        let mut a = engine("fn real_name() {}", "rs", &[]);
        let once = a.code("fn real_name() {}", &lang).unwrap();
        let token = token_regex().find(&once).unwrap().as_str().to_string();
        let trap = format!("const NOTE: u8 = {token};");
        assert!(a.code(&trap, &lang).is_err());
    }
}
