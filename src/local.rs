//! IA locale, servie par Ollama. C'est elle qui parle à l'utilisateur.

use crate::config::check_local_url;
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const PLAN_PROMPT: &str = r#"Tu es l'assistant local d'Anonimator. Tu parles avec le développeur et tu peux confier du travail de code à une IA en ligne, qui ne doit rien apprendre sur son identité, son entreprise ou son projet.

Réponds uniquement avec un objet JSON :
{"action":"reply","reply":"..."}  pour répondre toi-même (conversation, question de précision).
{"action":"delegate","instruction":"...","sensitive_terms":["..."]}  pour faire travailler l'IA en ligne.

Règles pour "instruction" :
- écrite en anglais, technique, précise et complète ;
- sans nom de personne, d'entreprise, de client ni de produit, sans contexte métier inutile ;
- les noms de fichiers et d'identifiants du code cités restent écrits à l'identique.

"sensitive_terms" : mots exacts du message du développeur qui l'identifient, lui ou son activité (noms propres, sociétés, clients, produits, domaines). Liste vide s'il n'y en a pas.

"reply" est écrit dans la langue du développeur."#;

const SUMMARY_PROMPT: &str = "Tu es l'assistant local d'Anonimator. Une IA en ligne vient de terminer un travail sur le code du développeur. Explique-lui brièvement, dans sa langue, ce qui a été fait et ce qu'il doit vérifier. Si des modifications sont listées, rappelle qu'elles attendent sa validation.";

#[derive(Debug, PartialEq)]
pub enum Plan {
    Reply(String),
    Delegate {
        instruction: String,
        sensitive_terms: Vec<String>,
    },
}

#[derive(Deserialize)]
struct RawPlan {
    action: String,
    #[serde(default)]
    reply: String,
    #[serde(default)]
    instruction: String,
    #[serde(default)]
    sensitive_terms: Vec<String>,
}

pub struct LocalAi {
    url: String,
    model: String,
}

impl LocalAi {
    pub fn new(url: &str, model: &str) -> Result<Self> {
        check_local_url(url)?;
        Ok(LocalAi {
            url: url.trim_end_matches('/').to_string(),
            model: model.to_string(),
        })
    }

    pub fn models(url: &str) -> Result<Vec<String>> {
        check_local_url(url)?;
        let endpoint = format!("{}/api/tags", url.trim_end_matches('/'));
        let body: Value = ureq::get(&endpoint)
            .timeout(Duration::from_secs(3))
            .call()
            .context("Ollama injoignable")?
            .into_json()?;
        Ok(body["models"]
            .as_array()
            .map(|list| {
                list.iter()
                    .filter_map(|m| m["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Décide quoi faire d'un message. Échoue plutôt que d'envoyer quoi que ce soit sans filtrage.
    pub fn plan(&self, history: &[Value], files: &[String]) -> Result<Plan> {
        let system = format!(
            "{PLAN_PROMPT}\n\nFichiers du projet :\n{}",
            files.join("\n")
        );
        let mut messages = vec![json!({"role": "system", "content": system})];
        messages.extend_from_slice(history);
        let raw = self.chat(&messages, true)?;
        parse_plan(&raw)
    }

    pub fn summarize(&self, report: &str) -> Result<String> {
        self.chat(
            &[
                json!({"role": "system", "content": SUMMARY_PROMPT}),
                json!({"role": "user", "content": report}),
            ],
            false,
        )
    }

    fn chat(&self, messages: &[Value], as_json: bool) -> Result<String> {
        let mut request = json!({"model": self.model, "stream": false, "messages": messages});
        if as_json {
            request["format"] = json!("json");
        }
        let endpoint = format!("{}/api/chat", self.url);
        let response = ureq::post(&endpoint)
            .timeout(Duration::from_secs(600))
            .send_json(request)
            .map_err(|error| match error {
                ureq::Error::Status(404, _) => anyhow!(
                    "le modèle local « {} » n'est pas installé (ollama pull {})",
                    self.model,
                    self.model
                ),
                ureq::Error::Status(code, _) => anyhow!("Ollama a répondu avec l'erreur {code}"),
                ureq::Error::Transport(_) => anyhow!(
                    "Ollama est injoignable à {} : lancez-le avec « ollama serve »",
                    self.url
                ),
            })?;
        let body: Value = response.into_json().context("réponse d'Ollama illisible")?;
        body["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("réponse d'Ollama sans contenu"))
    }
}

fn parse_plan(raw: &str) -> Result<Plan> {
    let plan: RawPlan = serde_json::from_str(raw.trim())
        .map_err(|_| anyhow!("l'IA locale n'a pas produit de JSON valide, rien n'a été envoyé"))?;
    match plan.action.as_str() {
        "reply" if !plan.reply.trim().is_empty() => Ok(Plan::Reply(plan.reply)),
        "delegate" if !plan.instruction.trim().is_empty() => Ok(Plan::Delegate {
            instruction: plan.instruction,
            sensitive_terms: plan.sensitive_terms,
        }),
        _ => Err(anyhow!(
            "réponse de l'IA locale incomplète, rien n'a été envoyé"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_parsing_fails_closed() {
        assert_eq!(
            parse_plan(r#"{"action":"reply","reply":"salut"}"#).unwrap(),
            Plan::Reply("salut".into())
        );
        let delegate =
            parse_plan(r#"{"action":"delegate","instruction":"do","sensitive_terms":["Acme"]}"#);
        assert!(matches!(delegate.unwrap(), Plan::Delegate { .. }));
        for bad in [
            "pas du json",
            r#"{"action":"delegate"}"#,
            r#"{"action":"autre"}"#,
        ] {
            assert!(parse_plan(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_a_non_local_endpoint() {
        assert!(LocalAi::new("https://example.com", "m").is_err());
    }
}
