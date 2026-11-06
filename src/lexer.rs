//! Lexer multi-langage volontairement simple. Invariant : la concaténation du texte
//! des tokens redonne exactement la source, quelle que soit l'entrée.

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Space,
    Punct,
    Ident,
    Number,
    Str,
    Comment,
}

#[derive(Clone, Copy, Debug)]
pub struct Token<'a> {
    pub kind: Kind,
    pub text: &'a str,
    /// Début et fin du contenu dans `text`, pour `Str` et `Comment`.
    pub body: (usize, usize),
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SingleQuote {
    /// `'abc'` est une chaîne (JS, Python, shell…).
    Str,
    /// `'a'` est un caractère, sinon une apostrophe de lifetime (Rust, C, Java…).
    Char,
    None,
}

#[derive(Clone, Copy, Debug)]
pub struct Lang {
    pub line_comments: &'static [&'static str],
    pub block_comment: Option<(&'static str, &'static str)>,
    pub single_quote: SingleQuote,
    pub triple_quotes: bool,
    pub backtick: bool,
    pub multiline_dq: bool,
    pub rust_raw: bool,
    /// `nom type` plutôt que `type nom` pour un paramètre sans deux-points (Go).
    pub name_first_params: bool,
    /// Fichier de données : `serde = "1"` n'y déclare pas de variable.
    pub data_only: bool,
}

const fn lang(
    line_comments: &'static [&'static str],
    block_comment: Option<(&'static str, &'static str)>,
    single_quote: SingleQuote,
) -> Lang {
    Lang {
        line_comments,
        block_comment,
        single_quote,
        triple_quotes: false,
        backtick: false,
        multiline_dq: false,
        rust_raw: false,
        name_first_params: false,
        data_only: false,
    }
}

const C_BLOCK: Option<(&str, &str)> = Some(("/*", "*/"));

/// Langage d'après l'extension. `None` : le fichier n'est pas traité comme du code.
pub fn lang_for_extension(ext: &str) -> Option<Lang> {
    let c_like = lang(&["//"], C_BLOCK, SingleQuote::Char);
    let hash = lang(&["#"], None, SingleQuote::Str);
    Some(match ext.to_ascii_lowercase().as_str() {
        "rs" => Lang {
            multiline_dq: true,
            rust_raw: true,
            ..c_like
        },
        "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" | "cs" | "java" | "m" | "mm" => c_like,
        "kt" | "kts" | "scala" | "swift" | "dart" => Lang {
            triple_quotes: true,
            ..c_like
        },
        "go" => Lang {
            backtick: true,
            name_first_params: true,
            ..c_like
        },
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Lang {
            backtick: true,
            ..lang(&["//"], C_BLOCK, SingleQuote::Str)
        },
        "php" => Lang {
            multiline_dq: true,
            ..lang(&["//", "#"], C_BLOCK, SingleQuote::Str)
        },
        "py" | "pyi" => Lang {
            triple_quotes: true,
            ..hash
        },
        "rb" | "pl" | "r" | "jl" | "ps1" => hash,
        "yaml" | "yml" => Lang {
            data_only: true,
            ..hash
        },
        "toml" => Lang {
            triple_quotes: true,
            data_only: true,
            ..hash
        },
        "sh" | "bash" | "zsh" => Lang {
            multiline_dq: true,
            ..hash
        },
        "sql" | "lua" => lang(&["--"], C_BLOCK, SingleQuote::Str),
        "css" | "scss" | "less" => lang(&[], C_BLOCK, SingleQuote::Str),
        "json" => Lang {
            data_only: true,
            ..lang(&[], None, SingleQuote::None)
        },
        _ => return None,
    })
}

pub fn lex<'a>(src: &'a str, lang: &Lang) -> Vec<Token<'a>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        let rest = &src[i..];
        let token = comment(rest, lang)
            .or_else(|| raw_string(rest, lang))
            .or_else(|| string(rest, lang))
            .unwrap_or_else(|| simple(rest));
        i += token.text.len();
        out.push(token);
    }
    out
}

fn comment<'a>(rest: &'a str, lang: &Lang) -> Option<Token<'a>> {
    if let Some((open, close)) = lang.block_comment {
        if let Some(after_open) = rest.strip_prefix(open) {
            let (body_end, end) = match after_open.find(close) {
                Some(p) => (open.len() + p, open.len() + p + close.len()),
                None => (rest.len(), rest.len()),
            };
            return Some(comment_token(&rest[..end], open.len(), body_end));
        }
    }
    for marker in lang.line_comments {
        if rest.starts_with(marker) {
            let end = rest.find('\n').unwrap_or(rest.len());
            let body_end = if rest[..end].ends_with('\r') {
                end - 1
            } else {
                end
            };
            return Some(comment_token(&rest[..end], marker.len(), body_end));
        }
    }
    None
}

fn comment_token(text: &str, start: usize, end: usize) -> Token<'_> {
    Token {
        kind: Kind::Comment,
        text,
        body: (start, end),
    }
}

fn raw_string<'a>(rest: &'a str, lang: &Lang) -> Option<Token<'a>> {
    if !lang.rust_raw {
        return None;
    }
    let after_prefix = rest.strip_prefix("br").or_else(|| rest.strip_prefix('r'))?;
    let hashes = after_prefix.bytes().take_while(|b| *b == b'#').count();
    if after_prefix.as_bytes().get(hashes) != Some(&b'"') {
        return None;
    }
    let start = rest.len() - after_prefix.len() + hashes + 1;
    let close = format!("\"{}", "#".repeat(hashes));
    let body_len = rest[start..].find(&close)?;
    let end = start + body_len + close.len();
    Some(Token {
        kind: Kind::Str,
        text: &rest[..end],
        body: (start, start + body_len),
    })
}

fn string<'a>(rest: &'a str, lang: &Lang) -> Option<Token<'a>> {
    if lang.triple_quotes {
        for quote in ["\"\"\"", "'''"] {
            if rest.starts_with(quote) {
                return delimited(rest, quote, true);
            }
        }
    }
    match rest.as_bytes()[0] {
        b'"' => delimited(rest, "\"", lang.multiline_dq),
        b'`' if lang.backtick => delimited(rest, "`", true),
        b'\'' => match lang.single_quote {
            SingleQuote::Str => delimited(rest, "'", false),
            SingleQuote::Char => char_literal(rest),
            SingleQuote::None => None,
        },
        _ => None,
    }
}

fn delimited<'a>(rest: &'a str, quote: &str, multiline: bool) -> Option<Token<'a>> {
    let start = quote.len();
    let mut chars = rest[start..].char_indices();
    while let Some((offset, c)) = chars.next() {
        let at = start + offset;
        if c == '\\' {
            chars.next();
        } else if rest[at..].starts_with(quote) {
            return Some(Token {
                kind: Kind::Str,
                text: &rest[..at + quote.len()],
                body: (start, at),
            });
        } else if c == '\n' && !multiline {
            return None;
        }
    }
    None
}

/// `'x'` et `'\n'` restent tels quels, `'a` (lifetime) retombe sur la ponctuation.
fn char_literal(rest: &str) -> Option<Token<'_>> {
    let mut chars = rest.char_indices().skip(1);
    let (_, first) = chars.next()?;
    if first == '\n' || first == '\'' {
        return None;
    }
    if first == '\\' {
        chars.next()?;
        for (at, c) in chars {
            if c == '\'' {
                return Some(punct_like(&rest[..at + 1]));
            }
            if c == '\n' || at > 12 {
                return None;
            }
        }
        return None;
    }
    let (at, close) = chars.next()?;
    (close == '\'').then(|| punct_like(&rest[..at + 1]))
}

fn punct_like(text: &str) -> Token<'_> {
    Token {
        kind: Kind::Number,
        text,
        body: (0, 0),
    }
}

fn simple(rest: &str) -> Token<'_> {
    let first = rest.chars().next().expect("rest n'est jamais vide");
    let run = |pred: &dyn Fn(char) -> bool| rest.find(|c| !pred(c)).unwrap_or(rest.len());
    let (kind, end) = if first.is_whitespace() {
        (Kind::Space, run(&char::is_whitespace))
    } else if first.is_alphabetic() || first == '_' {
        (Kind::Ident, run(&|c| c.is_alphanumeric() || c == '_'))
    } else if first.is_ascii_digit() {
        (Kind::Number, number_end(rest))
    } else {
        (Kind::Punct, first.len_utf8())
    };
    Token {
        kind,
        text: &rest[..end],
        body: (0, 0),
    }
}

/// Un point n'appartient au nombre que s'il précède un chiffre : `1.5`, mais pas `self.0.field`.
fn number_end(rest: &str) -> usize {
    let mut chars = rest.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        let next_is_digit = chars.peek().is_some_and(|(_, n)| n.is_ascii_digit());
        if !(c.is_alphanumeric() || c == '_' || (c == '.' && next_is_digit)) {
            return at;
        }
    }
    rest.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_after_tuple_index_is_an_identifier() {
        let toks = kinds("self.0.secret_field 1.5", &rust());
        assert!(toks.contains(&(Kind::Ident, "secret_field".into())));
        assert!(toks.contains(&(Kind::Number, "1.5".into())));
    }

    fn rust() -> Lang {
        lang_for_extension("rs").unwrap()
    }

    fn kinds(src: &str, lang: &Lang) -> Vec<(Kind, String)> {
        lex(src, lang)
            .into_iter()
            .filter(|t| t.kind != Kind::Space)
            .map(|t| (t.kind, t.text.to_string()))
            .collect()
    }

    #[test]
    fn tokens_concatenate_back_to_source() {
        let samples = [
            "fn a<'b>(c: &'b str) -> char { '\\n'; r#\"x\"y\"#; \"é\\\"\" } // fin\r\n/* non fermé",
            "\"non fermé\n'x",
            "é ü 日本語 'é' `",
        ];
        for ext in ["rs", "py", "ts", "json", "sql", "css"] {
            let lang = lang_for_extension(ext).unwrap();
            for src in samples {
                let joined: String = lex(src, &lang).iter().map(|t| t.text).collect();
                assert_eq!(joined, src, "extension {ext}");
            }
        }
    }

    #[test]
    fn rust_lifetime_is_not_a_string() {
        let toks = kinds("&'abc str 'x'", &rust());
        assert!(toks.contains(&(Kind::Ident, "abc".into())));
        assert!(!toks.iter().any(|(k, _)| *k == Kind::Str));
    }

    #[test]
    fn raw_strings_and_raw_identifiers() {
        let toks = kinds("r#\"secret\"# r#type", &rust());
        assert_eq!(toks[0], (Kind::Str, "r#\"secret\"#".into()));
        assert!(toks.contains(&(Kind::Ident, "type".into())));
    }

    #[test]
    fn comment_body_excludes_carriage_return() {
        let toks = lex("// hello\r\nx", &rust());
        let c = toks[0];
        assert_eq!(&c.text[c.body.0..c.body.1], " hello");
    }

    #[test]
    fn python_triple_quote_spans_lines() {
        let py = lang_for_extension("py").unwrap();
        let toks = kinds("\"\"\"a\nb\"\"\"", &py);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].0, Kind::Str);
    }

    #[test]
    fn numbers_are_not_identifiers() {
        let toks = kinds("0xFF 10u32", &rust());
        assert!(toks.iter().all(|(k, _)| *k == Kind::Number));
    }
}
