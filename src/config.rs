//! Réglages persistants. La clé d'API va dans le gestionnaire d'identifiants de l'OS,
//! jamais dans le fichier de configuration.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
pub const ANTHROPIC_MODEL: &str = "claude-opus-5-5";
pub const OPENAI_URL: &str = "https://api.openai.com/v1/chat/completions";
pub const CHATGPT_URL: &str = "https://api.openai.com/v1/responses";
pub const ANTHROPIC_KEYS_PAGE: &str = "https://platform.claude.com/settings/keys";

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum Provider {
    Anthropic,
    OpenAiCompatible,
    /// Forfait ChatGPT, via « Sign in with ChatGPT » : pas de clé d'API.
    ChatGptPlan,
}

impl Provider {
    fn key_name(self) -> Option<&'static str> {
        match self {
            Provider::Anthropic => Some("anthropic"),
            Provider::OpenAiCompatible => Some("openai-compatible"),
            Provider::ChatGptPlan => None,
        }
    }

    fn env_var(self) -> Option<&'static str> {
        match self {
            Provider::Anthropic => Some("ANTHROPIC_API_KEY"),
            Provider::OpenAiCompatible => Some("OPENAI_API_KEY"),
            Provider::ChatGptPlan => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub ollama_url: String,
    pub local_model: String,
    pub provider: Provider,
    pub remote_url: String,
    pub remote_model: String,
    pub workspace: Option<PathBuf>,
    pub require_approval: bool,
    pub allow_prose: bool,
    /// Mode auto : l'anonymiseur cherche seul, y compris les noms non déclarés par le projet.
    pub auto_anonymize: bool,
    /// Termes à masquer partout, un par ligne : client, société, produit…
    pub custom_terms: String,
    #[serde(skip)]
    pub api_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ollama_url: "http://127.0.0.1:11434".into(),
            local_model: "llama3.2".into(),
            provider: Provider::Anthropic,
            remote_url: ANTHROPIC_URL.into(),
            remote_model: ANTHROPIC_MODEL.into(),
            workspace: None,
            require_approval: true,
            allow_prose: false,
            auto_anonymize: true,
            custom_terms: String::new(),
            api_key: String::new(),
        }
    }
}

impl Config {
    pub fn terms(&self) -> Vec<String> {
        self.custom_terms
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }
}

pub fn data_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Anonimator")
}

pub fn load() -> Config {
    std::fs::read_to_string(data_dir().join("config.json"))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save(config: &Config) -> Result<()> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("config.json"), serde_json::to_vec_pretty(config)?)
        .context("écriture de la configuration")
}

pub fn load_api_key(provider: Provider) -> String {
    let (Some(name), Some(variable)) = (provider.key_name(), provider.env_var()) else {
        return String::new();
    };
    keyring::Entry::new("anonimator", name)
        .and_then(|entry| entry.get_password())
        .ok()
        .or_else(|| std::env::var(variable).ok())
        .unwrap_or_default()
}

pub fn save_api_key(provider: Provider, key: &str) -> Result<()> {
    let Some(name) = provider.key_name() else {
        bail!("ce mode de connexion n'utilise pas de clé d'API");
    };
    keyring::Entry::new("anonimator", name)
        .and_then(|entry| entry.set_password(key))
        .context("enregistrement de la clé dans le gestionnaire d'identifiants")
}

fn scheme_and_host(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    let host = match authority.strip_prefix('[') {
        Some(ipv6) => ipv6.split(']').next()?,
        None => authority.split(':').next()?,
    };
    Some((scheme, host))
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "::1") || host.starts_with("127.")
}

/// L'IA « locale » voit le vrai code : elle doit réellement être sur cette machine.
pub fn check_local_url(url: &str) -> Result<()> {
    match scheme_and_host(url) {
        Some((_, host)) if is_loopback(host) => Ok(()),
        _ => bail!("l'IA locale doit tourner sur cette machine (localhost), pas sur {url}"),
    }
}

/// La clé d'API ne doit pas circuler en clair hors de la machine.
pub fn check_remote_url(url: &str) -> Result<()> {
    match scheme_and_host(url) {
        Some(("https", _)) => Ok(()),
        Some((_, host)) if is_loopback(host) => Ok(()),
        _ => bail!("l'adresse de l'IA en ligne doit être en https : {url}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_url_must_be_loopback() {
        for ok in [
            "http://127.0.0.1:11434",
            "http://localhost:11434",
            "http://[::1]:11434",
        ] {
            assert!(check_local_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://192.168.1.5:11434",
            "https://ollama.example.com",
            "http://localhost.evil.com",
            "nimporte",
        ] {
            assert!(check_local_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn remote_url_must_be_https_unless_loopback() {
        assert!(check_remote_url(ANTHROPIC_URL).is_ok());
        assert!(check_remote_url("http://127.0.0.1:9000/v1/messages").is_ok());
        assert!(check_remote_url("http://api.example.com/v1").is_err());
    }
}
