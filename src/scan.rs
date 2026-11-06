//! Repère les identifiants déclarés par le projet : ce sont eux qui seront pseudonymisés.
//! Les noms venant des bibliothèques restent lisibles pour que l'IA en ligne reste utile.

use crate::keep::is_public;
use crate::lexer::{lex, Kind, Lang, Token};
use std::collections::HashSet;

const NAME_KEYWORDS: &[&str] = &[
    "fn",
    "def",
    "function",
    "func",
    "class",
    "struct",
    "enum",
    "trait",
    "type",
    "interface",
    "union",
    "mod",
    "module",
    "namespace",
    "package",
    "record",
    "object",
    "protocol",
    "alias",
    "macro_rules",
];
const TYPE_BODY_KEYWORDS: &[&str] = &[
    "struct",
    "class",
    "enum",
    "trait",
    "interface",
    "union",
    "record",
    "protocol",
    "object",
];
const CALLABLE_KEYWORDS: &[&str] = &["fn", "def", "function", "func"];
const BINDING_KEYWORDS: &[&str] = &["let", "const", "var", "val", "static", "local"];
const MODIFIERS: &[&str] = &[
    "pub",
    "public",
    "private",
    "protected",
    "internal",
    "readonly",
    "static",
    "final",
    "abstract",
    "async",
    "override",
    "const",
    "mut",
    "volatile",
    "transient",
    "virtual",
    "unsafe",
    "dyn",
    "ref",
    "sealed",
    "extern",
    "inline",
];

/// Racines qui désignent une API publique : leurs propriétés restent lisibles en mode auto.
const LIBRARY_GLOBALS: &[&str] = &[
    "console",
    "process",
    "window",
    "document",
    "navigator",
    "globalThis",
    "module",
    "exports",
    "os",
    "sys",
    "std",
    "core",
    "alloc",
    "fmt",
    "io",
];

/// Ajoute à `defs` les identifiants déclarés dans `src`.
pub fn collect_definitions(src: &str, lang: &Lang, defs: &mut HashSet<String>) {
    scan(src, lang, defs, false);
}

/// Mode auto : ajoute aussi les clés d'objets et les propriétés lues sur des données,
/// même si le projet ne les déclare pas. Les méthodes et les API importées restent lisibles.
pub fn collect_names_deep(src: &str, lang: &Lang, defs: &mut HashSet<String>) {
    scan(src, lang, defs, true);
}

fn scan(src: &str, lang: &Lang, defs: &mut HashSet<String>, deep: bool) {
    if lang.data_only {
        return;
    }
    let tokens = lex(src, lang);
    let imported = if deep {
        imported_names(&tokens)
    } else {
        HashSet::new()
    };
    let sig: Vec<Token> = tokens
        .into_iter()
        .filter(|t| !matches!(t.kind, Kind::Space | Kind::Comment))
        .collect();
    Scanner {
        sig: &sig,
        lang,
        defs,
        type_bodies: Vec::new(),
        pending_body: false,
        deep,
        imported,
    }
    .run();
}

/// Ajoute à `out` les noms importés depuis un paquet externe : ils sont publics par définition.
/// `project_roots` contient les modules du projet, dont les imports restent à masquer.
pub fn collect_public_imports(
    src: &str,
    lang: &Lang,
    project_roots: &HashSet<String>,
    out: &mut HashSet<String>,
) {
    if lang.data_only {
        return;
    }
    let tokens: Vec<Token> = lex(src, lang)
        .into_iter()
        .filter(|t| t.kind != Kind::Comment)
        .collect();
    let is_external = |root: &str| {
        let local = matches!(root, "" | "crate" | "self" | "super")
            || root.starts_with('.')
            || root.starts_with('/');
        !local && !project_roots.contains(root) && !project_roots.contains(&root.replace('-', "_"))
    };
    for (start, token) in tokens.iter().enumerate() {
        if token.kind != Kind::Ident || !matches!(token.text, "use" | "import" | "from") {
            continue;
        }
        let rest = || tokens[start + 1..].iter().filter(|t| t.kind != Kind::Space);
        // Python : `from paquet import a, b`. Le `from` de JavaScript est suivi d'une chaîne et ignoré ici.
        if token.text == "from" {
            let Some(first) = rest().next().filter(|t| t.kind == Kind::Ident) else {
                continue;
            };
            if !is_external(first.text) || !rest().any(|t| t.text == "import") {
                continue;
            }
            out.insert(first.text.to_string());
            let names = tokens[start + 1..]
                .iter()
                .skip_while(|t| t.text != "import")
                .skip(1);
            collect_statement_names(names, out);
            continue;
        }
        // Python après `from … import` : déjà traité, et sa racine n'est pas le premier nom.
        let after_from = tokens[..start]
            .iter()
            .rev()
            .take_while(|t| !t.text.contains('\n'))
            .any(|t| t.text == "from");
        if after_from {
            continue;
        }
        let mut names = HashSet::new();
        let source = collect_statement_names(tokens[start + 1..].iter(), &mut names);
        let root = match source {
            Some(path) => path
                .trim_start_matches('@')
                .split('/')
                .next()
                .unwrap_or("")
                .to_string(),
            None => rest()
                .find(|t| t.kind == Kind::Ident)
                .map_or(String::new(), |t| t.text.to_string()),
        };
        // Un import JavaScript relatif commence par un point, conservé dans `source`.
        let relative = source.is_some_and(|path| path.starts_with('.') || path.starts_with('/'));
        if !relative && is_external(&root) {
            out.extend(names);
        }
    }
}

/// Lit une instruction d'import. Renvoie le chemin de `from 'chemin'` s'il y en a un.
fn collect_statement_names<'t, 'a: 't>(
    tokens: impl Iterator<Item = &'t Token<'a>>,
    names: &mut HashSet<String>,
) -> Option<&'a str> {
    let mut depth = 0;
    let mut after_from = false;
    for token in tokens {
        match (token.kind, token.text) {
            (Kind::Space, text) if depth == 0 && text.contains('\n') && !after_from => return None,
            (Kind::Str, _) if after_from => return Some(&token.text[token.body.0..token.body.1]),
            (Kind::Punct, ";") => return None,
            (Kind::Ident, "from") if depth == 0 => after_from = true,
            (Kind::Punct, "{" | "(") => depth += 1,
            (Kind::Punct, "}" | ")") => depth -= 1,
            (Kind::Ident, name) if name != "as" && !after_from => {
                names.insert(name.to_string());
            }
            _ => {}
        }
    }
    None
}

/// Noms introduits par `import`, `use` ou `const x = require(…)`.
fn imported_names(tokens: &[Token]) -> HashSet<String> {
    let mut names = HashSet::new();
    for (start, token) in tokens.iter().enumerate() {
        if token.kind != Kind::Ident {
            continue;
        }
        if token.text == "require" {
            let mut before = tokens[..start]
                .iter()
                .rev()
                .filter(|t| t.kind != Kind::Space);
            if before.next().map(|t| t.text) == Some("=") {
                if let Some(name) = before.next().filter(|t| t.kind == Kind::Ident) {
                    names.insert(name.text.to_string());
                }
            }
        }
        if token.text != "import" && token.text != "use" {
            continue;
        }
        let mut depth = 0;
        for next in &tokens[start + 1..] {
            match (next.kind, next.text) {
                (Kind::Space, text) if depth == 0 && text.contains('\n') => break,
                (Kind::Punct, ";") | (Kind::Ident, "from") => break,
                (Kind::Punct, "{" | "(") => depth += 1,
                (Kind::Punct, "}" | ")") => depth -= 1,
                (Kind::Ident, name) => {
                    names.insert(name.to_string());
                }
                _ => {}
            }
        }
    }
    names
}

struct Scanner<'s, 'a> {
    sig: &'s [Token<'a>],
    lang: &'s Lang,
    defs: &'s mut HashSet<String>,
    deep: bool,
    imported: HashSet<String>,
    /// Profondeur d'accolades de chaque corps de type ouvert.
    type_bodies: Vec<i32>,
    pending_body: bool,
}

impl Scanner<'_, '_> {
    fn text(&self, i: usize) -> &str {
        self.sig.get(i).map_or("", |t| t.text)
    }

    fn is_ident(&self, i: usize) -> bool {
        self.sig.get(i).is_some_and(|t| t.kind == Kind::Ident)
    }

    fn add(&mut self, i: usize) {
        if self.is_ident(i) {
            let word = self.text(i).to_string();
            // Une seule lettre ne révèle rien et ferait bloquer `'l'` ou `1l` par l'audit.
            if word.chars().count() >= 2 && !is_public(&word) {
                self.defs.insert(word);
            }
        }
    }

    fn run(&mut self) {
        let mut braces = 0;
        let mut parens = 0;
        for i in 0..self.sig.len() {
            let text = self.text(i).to_string();
            match text.as_str() {
                "{" => {
                    braces += 1;
                    if self.pending_body {
                        self.type_bodies.push(braces);
                        self.pending_body = false;
                    }
                }
                "}" => {
                    if self.type_bodies.last() == Some(&braces) {
                        self.type_bodies.pop();
                    }
                    braces -= 1;
                }
                ";" => self.pending_body = false,
                "(" | "[" => parens += 1,
                ")" | "]" => parens -= 1,
                _ => {}
            }
            if self.type_bodies.last() == Some(&braces) {
                self.member(i);
            }
            if !self.is_ident(i) {
                if text == "=" && self.text(i + 1) == ">" {
                    self.arrow_params(i);
                }
                continue;
            }
            let previous = if i == 0 { "" } else { self.text(i - 1) };
            if previous == "." {
                let receiver = if i >= 2 { self.text(i - 2) } else { "" };
                let assigned = self.text(i + 1) == "=" && self.text(i + 2) != "=";
                if assigned && (receiver == "self" || receiver == "this") {
                    self.add(i);
                }
                let path_or_call = matches!(self.text(i + 1), "(" | "!") || self.text(i + 1) == ":";
                if self.deep && !path_or_call && !self.rooted_in_library(i) {
                    self.add(i);
                }
                continue;
            }
            let object_key =
                self.text(i + 1) == ":" && self.text(i + 2) != ":" && matches!(previous, "{" | ",");
            if self.deep && braces > 0 && object_key {
                self.add(i);
            }
            self.keyword(i, &text);
            let walrus = self.text(i + 1) == ":" && self.text(i + 2) == "=";
            let assign = self.text(i + 1) == "=" && !matches!(self.text(i + 2), "=" | ">");
            if walrus || (assign && parens == 0) {
                self.add(i);
            }
        }
    }

    /// Remonte `a.b.c` jusqu'à `a` : vrai pour un module importé ou une API publique comme `Math`.
    fn rooted_in_library(&self, property: usize) -> bool {
        let mut root = property;
        while root >= 2 && self.text(root - 1) == "." && self.is_ident(root - 2) {
            root -= 2;
        }
        if root == property || (root >= 1 && self.text(root - 1) == ".") {
            return false; // résultat d'un appel ou d'un index : rien ne prouve que c'est public
        }
        let name = self.text(root);
        self.imported.contains(name)
            || LIBRARY_GLOBALS.contains(&name)
            || (is_public(name) && name.chars().next().is_some_and(char::is_uppercase))
    }

    fn keyword(&mut self, i: usize, word: &str) {
        if NAME_KEYWORDS.contains(&word) {
            let mut name = i + 1;
            if self.text(name) == "!" {
                name += 1; // macro_rules!
            }
            if self.text(name) == "*" {
                name += 1; // function*
            }
            if self.text(name) == "(" && word == "func" {
                name = self.params(name) + 1; // récepteur Go
            }
            self.add(name);
            if TYPE_BODY_KEYWORDS.contains(&word) {
                self.pending_body = true;
            }
            if CALLABLE_KEYWORDS.contains(&word) {
                let mut open = name + 1;
                if self.text(open) == "<" {
                    open = self.skip_generics(open);
                }
                if self.text(open) == "(" {
                    self.params(open);
                }
            }
        } else if BINDING_KEYWORDS.contains(&word) {
            self.binding(i + 1);
        } else if word == "for" {
            self.for_bindings(i + 1);
        } else if word == "as" {
            self.add(i + 1);
        }
    }

    /// `let (a, b) = …`, `const { a, b } = …`, `const int x = …`.
    fn binding(&mut self, start: usize) {
        let mut depth = 0;
        let mut last_plain = None;
        let mut i = start;
        while i < self.sig.len() {
            match self.text(i) {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => {
                    depth -= 1;
                    if depth <= 0 {
                        break;
                    }
                }
                "=" | ";" | ":" if depth == 0 => break,
                _ if self.is_ident(i) => {
                    let word = self.text(i);
                    if depth > 0 {
                        self.add(i);
                    } else if !MODIFIERS.contains(&word) {
                        last_plain = Some(i);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if let Some(name) = last_plain {
            self.add(name);
        }
    }

    fn for_bindings(&mut self, start: usize) {
        let mut i = start;
        while i < self.sig.len() && i < start + 16 {
            let text = self.text(i);
            if matches!(text, "in" | "of" | "=" | ";" | "{") {
                return;
            }
            if self.is_ident(i) && !MODIFIERS.contains(&text) {
                self.add(i);
            }
            i += 1;
        }
    }

    fn skip_generics(&self, open: usize) -> usize {
        let mut depth = 0;
        for i in open..self.sig.len() {
            match self.text(i) {
                "<" => depth += 1,
                ">" => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                "(" | "{" | ";" => return i,
                _ => {}
            }
        }
        self.sig.len()
    }

    /// Parcourt `( … )` à partir de `open` et renvoie l'indice de la parenthèse fermante.
    fn params(&mut self, open: usize) -> usize {
        let mut depth = 0;
        let mut segment: Vec<usize> = Vec::new();
        let mut closed = false; // un `:` ou `=` a été rencontré dans ce paramètre
        let mut i = open;
        while i < self.sig.len() {
            let text = self.text(i);
            match text {
                "(" | "[" | "{" | "<" => depth += 1,
                ")" | "]" | "}" | ">" => {
                    depth -= 1;
                    if depth == 0 {
                        self.flush_param(&segment);
                        return i;
                    }
                }
                "," if depth == 1 => {
                    self.flush_param(&segment);
                    segment.clear();
                    closed = false;
                }
                // `Duration::from_secs(3)` est une expression, pas un nom de paramètre.
                ":" if depth == 1 && self.text(i + 1) == ":" => {
                    segment.clear();
                    closed = true;
                }
                ":" | "=" if depth == 1 => closed = true,
                _ if depth == 1 && !closed && self.is_ident(i) && !MODIFIERS.contains(&text) => {
                    segment.push(i);
                }
                _ => {}
            }
            i += 1;
        }
        i
    }

    fn flush_param(&mut self, segment: &[usize]) {
        let name = if self.lang.name_first_params {
            segment.first()
        } else {
            segment.last()
        };
        if let Some(name) = name {
            self.add(*name);
        }
    }

    /// `(a, b) =>` et `x =>`, à partir de l'indice du `=`.
    fn arrow_params(&mut self, arrow: usize) {
        if arrow == 0 {
            return;
        }
        if self.is_ident(arrow - 1) {
            // `Kind::Foo =>` désigne une variante existante, pas un paramètre.
            if arrow < 2 || self.text(arrow - 2) != ":" {
                self.add(arrow - 1);
            }
        } else if self.text(arrow - 1) == ")" {
            let mut depth = 0;
            let mut i = arrow - 1;
            loop {
                match self.text(i) {
                    ")" => depth += 1,
                    "(" => {
                        depth -= 1;
                        if depth == 0 {
                            // `Err(x) =>` est un motif, seul `(a, b) =>` déclare des paramètres.
                            let before = if i == 0 { "" } else { self.text(i - 1) };
                            let is_pattern = i > 0 && self.is_ident(i - 1) && before != "async";
                            if !is_pattern {
                                self.params(i);
                            }
                            return;
                        }
                    }
                    _ => {}
                }
                if i == 0 {
                    return;
                }
                i -= 1;
            }
        }
    }

    /// Champ, méthode ou variante au début d'une déclaration, dans un corps de type.
    fn member(&mut self, i: usize) {
        if !matches!(self.text(i), "{" | ";" | "," | "}" | "]" | ")") {
            return;
        }
        let mut name = i + 1;
        while self.is_ident(name) && MODIFIERS.contains(&self.text(name)) {
            name += 1;
        }
        if self.text(name) == "(" {
            return; // pub(crate) : on reprendra à la parenthèse fermante
        }
        if !self.is_ident(name) {
            return;
        }
        if self.is_ident(name + 1) {
            // `String nom;` en C, Java…
            if matches!(self.text(name + 2), ";" | "=" | "(") {
                self.add(name + 1);
            }
            return;
        }
        if matches!(
            self.text(name + 1),
            ":" | "," | "=" | "(" | ";" | "?" | "}" | "{"
        ) {
            self.add(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lang_for_extension;

    fn defs(ext: &str, src: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        collect_definitions(src, &lang_for_extension(ext).unwrap(), &mut out);
        out
    }

    fn has(set: &HashSet<String>, words: &[&str]) {
        for word in words {
            assert!(set.contains(*word), "{word} absent de {set:?}");
        }
    }

    fn deep(ext: &str, src: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        collect_names_deep(src, &lang_for_extension(ext).unwrap(), &mut out);
        out
    }

    #[test]
    fn deep_scan_finds_object_keys_and_data_properties() {
        let d = deep(
            "ts",
            "const order = { montantHt: 3, tauxRemise: 0.2 };\nconsole.log(reponse.data.margeNette, facture.clientCode);\n",
        );
        has(&d, &["montantHt", "tauxRemise", "margeNette", "clientCode"]);
    }

    #[test]
    fn deep_scan_leaves_public_apis_readable() {
        let d = deep(
            "ts",
            "import fs from 'fs';\nconst path0 = require('path');\nfs.promises.readFile(x);\npath0.sep;\nMath.PI;\nconsole.log(document.title);\nitems.flatMap(f);\n",
        );
        for public in ["promises", "readFile", "sep", "PI", "flatMap", "title"] {
            assert!(!d.contains(public), "{public} masqué : {d:?}");
        }
        let py = deep("py", "import numpy as np\nprint(np.pi)\nos.environ\n");
        assert!(!py.contains("pi") && !py.contains("environ"), "{py:?}");
        let rust = deep("rs", "use std::fmt::{Debug, Write};\nstd::mem::swap(a, b);\nlet v = x.iter().collect::<Vec<_>>();\n");
        for public in ["mem", "swap", "iter", "collect"] {
            assert!(!rust.contains(public), "{public} masqué : {rust:?}");
        }
    }

    fn public_imports(ext: &str, src: &str) -> HashSet<String> {
        let roots: HashSet<String> = ["billing", "config", "acme_pay"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut out = HashSet::new();
        collect_public_imports(src, &lang_for_extension(ext).unwrap(), &roots, &mut out);
        out
    }

    #[test]
    fn external_imports_are_public_but_project_imports_are_not() {
        let rust = public_imports(
            "rs",
            "use std::time::Duration;\nuse serde_json::{json, Value};\nuse crate::vault::Secret;\nuse super::Inner;\nuse billing::Invoice;\nuse acme_pay::Ledger;\n",
        );
        has(&rust, &["Duration", "json", "Value", "serde_json"]);
        for private in [
            "Secret", "Inner", "Invoice", "Ledger", "billing", "acme_pay",
        ] {
            assert!(!rust.contains(private), "{private} rendu public : {rust:?}");
        }

        let py = public_imports(
            "py",
            "from numpy import array, zeros\nimport pandas as pd\nfrom config import db_secret\nfrom .local import helper_fn\nimport billing\n",
        );
        has(&py, &["numpy", "array", "zeros", "pandas", "pd"]);
        for private in ["db_secret", "helper_fn", "billing", "config"] {
            assert!(!py.contains(private), "{private} rendu public : {py:?}");
        }

        let ts = public_imports(
            "ts",
            "import React, { useState } from 'react';\nimport { Button } from '@mui/material';\nimport { priv } from './local';\nimport { other } from 'billing/x';\n",
        );
        has(&ts, &["React", "useState", "Button"]);
        for private in ["priv", "other"] {
            assert!(!ts.contains(private), "{private} rendu public : {ts:?}");
        }
    }

    #[test]
    fn expressions_are_not_mistaken_for_parameters() {
        let d = deep(
            "rs",
            "fn run(delay: Duration) {\n  match call(Duration::from_secs(3)) {\n    Err(ureq::Error::Status(code, body)) => stop(),\n    Ok(ErrorKind::WouldBlock) => stop(),\n    Kind::Other => stop(),\n    _ => stop(),\n  }\n}\n",
        );
        for public in [
            "Duration",
            "ureq",
            "Status",
            "ErrorKind",
            "Other",
            "WouldBlock",
        ] {
            assert!(!d.contains(public), "{public} masqué : {d:?}");
        }
        assert!(d.contains("delay"));
        let ts = deep("ts", "const f = async (firstArg, secondArg) => firstArg;\nconst g = (thirdArg) => thirdArg;\n");
        has(&ts, &["firstArg", "secondArg", "thirdArg"]);
    }

    #[test]
    fn plain_scan_keeps_previous_behaviour() {
        let d = defs(
            "ts",
            "const order = { montantHt: 3 };\nfacture.clientCode;\n",
        );
        assert!(!d.contains("montantHt") && !d.contains("clientCode"));
    }

    #[test]
    fn data_files_declare_nothing() {
        assert!(defs("toml", "serde = \"1\"\nanyhow = \"1\"\n").is_empty());
        assert!(defs("json", "{\"name\": 1}").is_empty());
    }

    #[test]
    fn rust_declarations() {
        let d = defs(
            "rs",
            "pub struct Invoice { pub amount_due: u32, customer_ref: String }\n\
             enum Tier { Gold, Silver(u8) }\n\
             pub fn compute_tax<T>(rate_pct: f32, mut base_amount: f32) -> f32 { let adjusted = 1.0; adjusted }\n\
             let (left_part, right_part) = split_it();",
        );
        has(
            &d,
            &[
                "Invoice",
                "amount_due",
                "customer_ref",
                "Tier",
                "Gold",
                "Silver",
            ],
        );
        has(
            &d,
            &[
                "compute_tax",
                "rate_pct",
                "base_amount",
                "adjusted",
                "left_part",
                "right_part",
            ],
        );
        assert!(!d.contains("f32"));
        assert!(
            !d.contains("split_it"),
            "un simple appel n'est pas une déclaration"
        );
    }

    #[test]
    fn python_declarations() {
        let d = defs(
            "py",
            "class Ledger:\n    def post_entry(self, account_no, amount=0):\n        self.balance_due = amount\n\
             \n\nfor row_item in rows:\n    total_paid = 1\nimport numpy as np\nprint(sep_char=1)\n",
        );
        has(
            &d,
            &[
                "Ledger",
                "post_entry",
                "account_no",
                "amount",
                "balance_due",
                "row_item",
                "total_paid",
                "np",
            ],
        );
        assert!(
            !d.contains("sep_char"),
            "un argument nommé n'est pas une déclaration"
        );
    }

    #[test]
    fn typescript_declarations() {
        let d = defs(
            "ts",
            "interface Customer { fullName: string; vipLevel?: number }\n\
             export const fetchCustomer = async (customerId: string) => { const { planCode, region } = await load(customerId); };\n\
             function* walkTree(startNode) {}\n",
        );
        has(
            &d,
            &[
                "Customer",
                "fullName",
                "vipLevel",
                "fetchCustomer",
                "customerId",
                "planCode",
                "region",
                "walkTree",
                "startNode",
            ],
        );
    }

    #[test]
    fn go_declarations() {
        let d = defs(
            "go",
            "package billing\ntype Account struct {\n}\nfunc (acct *Account) Charge(amountCents int) error {\n  feeTotal := 1\n  return nil\n}\n",
        );
        has(
            &d,
            &[
                "billing",
                "Account",
                "acct",
                "Charge",
                "amountCents",
                "feeTotal",
            ],
        );
    }

    #[test]
    fn java_like_declarations() {
        let d = defs(
            "java",
            "public class Payroll { private String employeeCode; public int netPay(int grossPay, final int bonusPart) { return 1; } }",
        );
        has(&d, &["Payroll", "employeeCode"]);
        assert!(d.contains("netPay"));
    }
}
