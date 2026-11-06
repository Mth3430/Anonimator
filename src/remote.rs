//! IA en ligne. Ce module ne reçoit que du contenu déjà anonymisé par `agent`.

use crate::chatgpt::ChatGptAuth;
use crate::config::{check_remote_url, Config, Provider};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::time::Duration;

const ANTHROPIC_VERSION: &str = "2026-10-21";
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
const FALLBACK_MODELS: &[&str] = &[
    "claude-opus-5-5",
    "claude-opus-5",
    "claude-fable-5-1",
    "claude-sonnet-5-5",
];
const MAX_TOKENS: u32 = 16_000;
const MAX_ATTEMPTS: u32 = 3;

pub const SYSTEM_PROMPT: &str = "You are a senior software engineer working on a codebase through tools. \
Names in this codebase are replaced by opaque placeholders: identifiers look like zq_a1b2c3, Zqa1b2c3 or ZQ_A1B2C3; \
string contents look like zs_a1b2c3; comments look like zc_a1b2c3; other masked values look like zp_a1b2c3. \
Path segments are masked the same way. Treat each placeholder as the real name: keep it byte-for-byte, never rename it or change its case, \
and do not try to guess what it stands for. Masked strings and comments carry their original meaning, so leave them where they are unless the task requires otherwise. \
Give new identifiers clear, generic names. Use the tools to inspect the code before changing it. \
Your edits are staged for human review and you cannot run code. When finished, reply with a short summary.";

#[derive(Debug)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input: Value,
}

#[derive(Debug, Default)]
pub struct Turn {
    pub text: String,
    pub calls: Vec<ToolCall>,
}

pub struct ToolOutcome {
    pub id: String,
    pub content: String,
    pub is_error: bool,
}

fn tools() -> Vec<(&'static str, &'static str, Value)> {
    let path =
        json!({"type": "string", "description": "File path, exactly as listed by list_files"});
    vec![
        (
            "list_files",
            "List the files of the project.",
            json!({"type": "object", "properties": {}}),
        ),
        (
            "read_file",
            "Read a whole file.",
            json!({"type": "object", "properties": {"path": path}, "required": ["path"]}),
        ),
        (
            "search",
            "Find a literal string across the project. Returns path:line:text.",
            json!({"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
        ),
        (
            "write_file",
            "Create a file or replace it entirely.",
            json!({"type": "object", "properties": {"path": path, "content": {"type": "string"}}, "required": ["path", "content"]}),
        ),
        (
            "edit_file",
            "Replace one exact occurrence of old_text with new_text. Fails unless old_text occurs exactly once.",
            json!({"type": "object", "properties": {"path": path, "old_text": {"type": "string"}, "new_text": {"type": "string"}}, "required": ["path", "old_text", "new_text"]}),
        ),
    ]
}

pub struct RemoteAi {
    provider: Provider,
    url: String,
    model: String,
    api_key: String,
    /// Historique envoyé tel quel à chaque requête. Il ne fait que s'allonger :
    /// les réponses Anthropic y restent intactes, blocs de réflexion compris.
    messages: Vec<Value>,
}

impl RemoteAi {
    pub fn new(config: &Config) -> Result<Self> {
        check_remote_url(&config.remote_url)?;
        if config.remote_model.trim().is_empty() {
            bail!("indiquez le modèle de l'IA en ligne dans les réglages");
        }
        if config.provider != Provider::ChatGptPlan && config.api_key.trim().is_empty() {
            bail!("connectez d'abord une IA en ligne : ChatGPT ou une clé Claude");
        }
        Ok(RemoteAi {
            provider: config.provider,
            url: config.remote_url.clone(),
            model: config.remote_model.clone(),
            api_key: config.api_key.clone(),
            messages: Vec::new(),
        })
    }

    pub fn push_user(&mut self, text: &str) {
        self.messages.push(json!({"role": "user", "content": text}));
    }

    pub fn push_results(&mut self, results: &[ToolOutcome]) {
        match self.provider {
            Provider::Anthropic => {
                let blocks: Vec<Value> = results
                    .iter()
                    .map(|r| {
                        json!({"type": "tool_result", "tool_use_id": r.id, "content": r.content, "is_error": r.is_error})
                    })
                    .collect();
                self.messages
                    .push(json!({"role": "user", "content": blocks}));
            }
            Provider::OpenAiCompatible | Provider::Gemini => {
                for r in results {
                    self.messages
                        .push(json!({"role": "tool", "tool_call_id": r.id, "content": r.content}));
                }
            }
            Provider::ChatGptPlan => {
                for r in results {
                    let output = if r.is_error {
                        format!("ERROR: {}", r.content)
                    } else {
                        r.content.clone()
                    };
                    self.messages.push(
                        json!({"type": "function_call_output", "call_id": r.id, "output": output}),
                    );
                }
            }
        }
    }

    /// Envoie l'historique et ajoute la réponse à celui-ci.
    pub fn step(&mut self, chatgpt: &mut ChatGptAuth) -> Result<Turn> {
        match self.provider {
            Provider::Anthropic => self.step_anthropic(),
            Provider::OpenAiCompatible | Provider::Gemini => self.step_openai(),
            Provider::ChatGptPlan => self.step_chatgpt(chatgpt),
        }
    }

    /// Forfait ChatGPT : `store` à false et flux obligatoires, donc tout l'historique
    /// est renvoyé à chaque tour, éléments de raisonnement compris.
    fn step_chatgpt(&mut self, auth: &mut ChatGptAuth) -> Result<Turn> {
        let token = auth.access_token()?;
        let tool_defs: Vec<Value> = tools()
            .into_iter()
            .map(|(name, description, schema)| {
                json!({"type": "function", "name": name, "description": description, "parameters": schema, "strict": false})
            })
            .collect();
        let body = json!({
            "model": self.model,
            "instructions": SYSTEM_PROMPT,
            "input": self.messages,
            "tools": tool_defs,
            "include": ["reasoning.encrypted_content"],
            "store": false,
            "stream": true,
        });
        // OpenAI demande de signaler les limites d'usage sans relancer, et de refuser les redirections.
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(Duration::from_secs(600))
            .build();
        let response = agent
            .post(&self.url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Accept", "text/event-stream")
            .send_json(&body);
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(status, response)) => {
                let detail: Value = response.into_json().unwrap_or(Value::Null);
                bail!(
                    "{}",
                    chatgpt_error(
                        detail["error"]["code"].as_str(),
                        detail["error"]["param"].as_str(),
                        Some(status)
                    )
                );
            }
            Err(error) => bail!("IA en ligne injoignable : {error}"),
        };
        if response.content_type() != "text/event-stream" {
            bail!("réponse inattendue de ChatGPT : flux absent");
        }
        let completed = read_response_stream(BufReader::new(response.into_reader()))?;
        let output = completed["output"]
            .as_array()
            .ok_or_else(|| anyhow!("réponse sans contenu"))?;
        let turn = turn_from_output(output);
        // Chaque élément est conservé tel quel, comme l'exige le mode sans stockage.
        self.messages.extend(output.iter().cloned());
        Ok(turn)
    }

    fn step_anthropic(&mut self) -> Result<Turn> {
        let tool_defs: Vec<Value> = tools()
            .into_iter()
            .map(|(name, description, schema)| {
                json!({"name": name, "description": description, "input_schema": schema})
            })
            .collect();
        let mut body = json!({
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": SYSTEM_PROMPT,
            "tools": tool_defs,
            "output_config": {"effort": "high"},
            "messages": self.messages,
        });
        let mut headers = vec![
            ("x-api-key", self.api_key.clone()),
            ("anthropic-version", ANTHROPIC_VERSION.to_string()),
        ];
        if FALLBACK_MODELS.contains(&self.model.as_str()) {
            body["fallbacks"] = json!("default");
            headers.push(("anthropic-beta", FALLBACK_BETA.to_string()));
        }
        let response = post(&self.url, &headers, &body)?;
        let content = response["content"].clone();
        match response["stop_reason"].as_str().unwrap_or("") {
            "refusal" => bail!("l'IA en ligne a refusé cette demande"),
            "max_tokens" => {
                bail!("réponse de l'IA en ligne tronquée : demandez une tâche plus petite")
            }
            _ => {}
        }
        let blocks = content
            .as_array()
            .ok_or_else(|| anyhow!("réponse sans contenu"))?;
        let mut turn = Turn::default();
        for block in blocks {
            match block["type"].as_str() {
                Some("text") => turn.text.push_str(block["text"].as_str().unwrap_or("")),
                Some("tool_use") => turn.calls.push(ToolCall {
                    id: block["id"].as_str().unwrap_or("").to_string(),
                    name: block["name"].as_str().unwrap_or("").to_string(),
                    input: block["input"].clone(),
                }),
                _ => {}
            }
        }
        self.messages
            .push(json!({"role": "assistant", "content": content}));
        Ok(turn)
    }

    fn step_openai(&mut self) -> Result<Turn> {
        let tool_defs: Vec<Value> = tools()
            .into_iter()
            .map(|(name, description, schema)| {
                let mut function =
                    json!({"name": name, "description": description, "parameters": schema});
                // Gemini accepte mal un objet sans propriétés : un outil sans argument s'en passe.
                let no_arguments = function["parameters"]["properties"]
                    .as_object()
                    .is_some_and(|properties| properties.is_empty());
                if self.provider == Provider::Gemini && no_arguments {
                    function
                        .as_object_mut()
                        .expect("objet ci-dessus")
                        .remove("parameters");
                }
                json!({"type": "function", "function": function})
            })
            .collect();
        let mut messages = vec![json!({"role": "system", "content": SYSTEM_PROMPT})];
        messages.extend_from_slice(&self.messages);
        let body = json!({"model": self.model, "tools": tool_defs, "messages": messages});
        let headers = [("Authorization", format!("Bearer {}", self.api_key))];
        let response = post(&self.url, &headers, &body)?;
        let choice = &response["choices"][0];
        match choice["finish_reason"].as_str().unwrap_or("") {
            "length" => bail!("réponse de l'IA en ligne tronquée : demandez une tâche plus petite"),
            "content_filter" => bail!("l'IA en ligne a refusé cette demande"),
            _ => {}
        }
        let message = choice["message"].clone();
        if !message.is_object() {
            bail!("réponse sans contenu");
        }
        let mut turn = Turn {
            text: message["content"].as_str().unwrap_or("").to_string(),
            calls: Vec::new(),
        };
        for call in message["tool_calls"].as_array().into_iter().flatten() {
            let arguments = call["function"]["arguments"].as_str().unwrap_or("{}");
            turn.calls.push(ToolCall {
                id: call["id"].as_str().unwrap_or("").to_string(),
                name: call["function"]["name"].as_str().unwrap_or("").to_string(),
                // Des arguments invalides deviennent une erreur d'outil, renvoyée à l'IA.
                input: serde_json::from_str(arguments).unwrap_or(Value::Null),
            });
        }
        self.messages.push(message);
        Ok(turn)
    }
}

/// Lit le flux jusqu'à `response.completed` et renvoie l'objet réponse. Tout autre fin est une erreur.
fn read_response_stream(reader: impl BufRead) -> Result<Value> {
    let mut data = String::new();
    for line in reader.lines() {
        let line = line.context("flux ChatGPT interrompu")?;
        if let Some(chunk) = line.strip_prefix("data:") {
            data.push_str(chunk.trim_start());
            continue;
        }
        if !line.trim().is_empty() || data.is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(&data).context("flux ChatGPT illisible")?;
        data.clear();
        match event["type"].as_str() {
            Some("response.completed") => return Ok(event["response"].clone()),
            Some("response.failed") => {
                let error = &event["response"]["error"];
                bail!(
                    "{}",
                    chatgpt_error(error["code"].as_str(), error["param"].as_str(), None)
                );
            }
            Some("error") => {
                let code = event["error"]["code"].as_str().or(event["code"].as_str());
                let param = event["error"]["param"].as_str().or(event["param"].as_str());
                bail!("{}", chatgpt_error(code, param, None));
            }
            Some("response.incomplete") => {
                bail!("réponse de l'IA en ligne tronquée : demandez une tâche plus petite")
            }
            _ => {}
        }
    }
    bail!("flux ChatGPT interrompu avant la fin de la réponse")
}

fn turn_from_output(output: &[Value]) -> Turn {
    let mut turn = Turn::default();
    for item in output {
        match item["type"].as_str() {
            Some("message") => {
                for part in item["content"].as_array().into_iter().flatten() {
                    if part["type"].as_str() == Some("output_text") {
                        turn.text.push_str(part["text"].as_str().unwrap_or(""));
                    }
                }
            }
            Some("function_call") => turn.calls.push(ToolCall {
                id: item["call_id"].as_str().unwrap_or("").to_string(),
                name: item["name"].as_str().unwrap_or("").to_string(),
                // Des arguments invalides deviennent une erreur d'outil, renvoyée à l'IA.
                input: serde_json::from_str(item["arguments"].as_str().unwrap_or("{}"))
                    .unwrap_or(Value::Null),
            }),
            _ => {}
        }
    }
    turn
}

fn chatgpt_error(code: Option<&str>, param: Option<&str>, status: Option<u16>) -> String {
    match code {
        Some("subscription_sharing_usage_limit_exceeded") => {
            "limite d'usage atteinte : consultez « Manage usage » dans ChatGPT".into()
        }
        Some("subscription_sharing_user_not_eligible") => {
            "ce compte ChatGPT ne peut pas utiliser son forfait dans cette application".into()
        }
        Some(
            "subscription_sharing_usage_unavailable" | "subscription_sharing_user_unavailable",
        ) => "forfait ChatGPT momentanément indisponible : réessayez plus tard".into(),
        Some("subscription_sharing_unsupported_capability") => {
            format!(
                "fonction non prise en charge par le forfait ChatGPT : {}",
                param.unwrap_or("non précisée")
            )
        }
        Some("subscription_sharing_invalid_user") => {
            "connexion ChatGPT refusée : essayez de vous reconnecter".into()
        }
        Some(other) => format!("erreur ChatGPT : {other}"),
        None => match status {
            Some(401) => "connexion ChatGPT refusée : vérifiez le compte utilisé".into(),
            Some(403) => {
                "accès refusé par ChatGPT, par exemple selon la région ou le compte".into()
            }
            Some(503) => "forfait ChatGPT momentanément indisponible : réessayez plus tard".into(),
            Some(other) => format!("erreur ChatGPT {other}"),
            None => "erreur ChatGPT sans précision".into(),
        },
    }
}

fn post(url: &str, headers: &[(&str, String)], body: &Value) -> Result<Value> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut request = ureq::post(url).timeout(Duration::from_secs(600));
        for (name, value) in headers {
            request = request.set(name, value);
        }
        match request.send_json(body) {
            Ok(response) => {
                return response
                    .into_json()
                    .context("réponse de l'IA en ligne illisible")
            }
            Err(ureq::Error::Status(code, response)) => {
                let retryable = code == 408 || code == 409 || code == 429 || code >= 500;
                if retryable && attempt < MAX_ATTEMPTS {
                    let wait = response
                        .header("retry-after")
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(2u64.pow(attempt))
                        .min(60);
                    std::thread::sleep(Duration::from_secs(wait));
                    continue;
                }
                let detail: String = response
                    .into_string()
                    .unwrap_or_default()
                    .chars()
                    .take(400)
                    .collect();
                bail!("l'IA en ligne a répondu {code} : {detail}");
            }
            Err(ureq::Error::Transport(error)) => {
                if attempt < MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                    continue;
                }
                bail!("IA en ligne injoignable : {error}");
            }
        }
    }
}
