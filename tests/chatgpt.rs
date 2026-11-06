//! Connexion ChatGPT et boucle d'outils contre de faux serveurs OpenAI : le navigateur est simulé,
//! mais l'écoute locale, le PKCE, la vérification de signature et le flux SSE sont les vrais.

use anonimator::chatgpt::{ChatGptAuth, Endpoints, Secrets};
use anonimator::config::{Config, Provider};
use anonimator::remote::{RemoteAi, ToolOutcome};
use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const CLIENT: &str = "oaiapp_test123";

#[derive(Clone)]
struct MemorySecrets(Arc<Mutex<Option<String>>>);

impl Secrets for MemorySecrets {
    fn get(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn set(&mut self, value: &str) -> Result<()> {
        *self.0.lock().unwrap() = Some(value.to_string());
        Ok(())
    }
    fn clear(&mut self) {
        *self.0.lock().unwrap() = None;
    }
}

struct TestKey {
    pem: String,
    n: String,
    e: String,
}

fn key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        TestKey {
            pem: private
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap()
                .to_string(),
            n: URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
        }
    })
}

fn sign(claims: Value) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("k1".into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(key().pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[derive(Default)]
struct Idp {
    issuer: String,
    nonce: String,
    expected_challenge: String,
    token_forms: Vec<String>,
    responses: Vec<Value>,
    tamper: Option<&'static str>,
    grant_plan: bool,
    refresh_error: Option<&'static str>,
    exchange_refused: bool,
    expires_in: u64,
}

fn form_field(form: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(form.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn id_token(idp: &Idp) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "iss": idp.issuer, "aud": CLIENT, "sub": "user-1", "email": "dev@example.test",
        "iat": now, "exp": now + 3600, "nonce": idp.nonce,
    });
    match idp.tamper {
        Some("nonce") => claims["nonce"] = json!("autre"),
        Some("audience") => claims["aud"] = json!("autre-app"),
        Some("issuer") => claims["iss"] = json!("https://evil.example"),
        Some("expired") => claims["exp"] = json!(now - 3600),
        Some("subject") => claims["sub"] = json!("user-2"),
        Some("forged") => {
            let other = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
            let pem = other.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
            let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("k1".into());
            return encode(
                &header,
                &claims,
                &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            )
            .unwrap();
        }
        _ => {}
    }
    sign(claims)
}

fn start_server(idp: Arc<Mutex<Idp>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    idp.lock().unwrap().issuer = base.clone();
    let shared = idp;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let (head, body) = read_request(&mut stream);
            let target = head.split(' ').nth(1).unwrap_or("").to_string();
            let mut state = shared.lock().unwrap();
            let (status, content_type, text) = match target.as_str() {
                "/jwks" => ("200 OK", "application/json", json!({"keys": [{
                    "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1", "n": key().n, "e": key().e
                }]}).to_string()),
                "/token" => {
                    state.token_forms.push(body.clone());
                    let grant = form_field(&body, "grant_type").unwrap_or_default();
                    if grant == "authorization_code" && state.exchange_refused {
                        ("400 Bad Request", "application/json", json!({
                            "error": "invalid_grant", "error_description": "A required permission is unavailable."
                        }).to_string())
                    } else if grant == "refresh_token" && state.refresh_error.is_some() {
                        ("400 Bad Request", "application/json", json!({"error": state.refresh_error}).to_string())
                    } else {
                        if grant == "authorization_code" {
                            let verifier = form_field(&body, "code_verifier").unwrap_or_default();
                            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
                            assert_eq!(challenge, state.expected_challenge, "PKCE invalide");
                        }
                        let scope = if state.grant_plan { "openid email chatgpt.tokens.use.direct" } else { "openid email" };
                        let suffix = state.token_forms.len();
                        let expires = state.expires_in;
                        ("200 OK", "application/json", json!({
                            "access_token": format!("access-{suffix}"), "refresh_token": format!("refresh-{suffix}"),
                            "id_token": id_token(&state), "token_type": "Bearer", "expires_in": expires, "scope": scope,
                        }).to_string())
                    }
                }
                "/models" => ("200 OK", "application/json", json!({"models": [
                    {"slug": "modele-visible", "visibility": "list"}, {"slug": "modele-cache", "visibility": "hide"}
                ]}).to_string()),
                "/responses" => {
                    let parsed: Value = serde_json::from_str(&body).unwrap();
                    assert!(head.to_lowercase().contains("authorization: bearer access-"), "{head}");
                    state.responses.push(parsed);
                    let index = state.responses.len();
                    ("200 OK", "text/event-stream", sse_for(index))
                }
                _ => ("404 Not Found", "text/plain", String::new()),
            };
            drop(state);
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    base
}

fn read_request(stream: &mut std::net::TcpStream) -> (String, String) {
    let mut data = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream.read(&mut chunk).unwrap();
        data.extend_from_slice(&chunk[..read]);
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).to_string();
            let length: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            while data.len() < end + 4 + length {
                let read = stream.read(&mut chunk).unwrap();
                data.extend_from_slice(&chunk[..read]);
            }
            return (head, String::from_utf8_lossy(&data[end + 4..]).to_string());
        }
        if read == 0 {
            return (String::new(), String::new());
        }
    }
}

fn sse(events: &[Value]) -> String {
    events
        .iter()
        .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap()))
        .collect()
}

fn sse_for(index: usize) -> String {
    match index {
        1 => sse(&[
            json!({"type": "response.created"}),
            json!({"type": "response.completed", "response": {"output": [
                {"type": "reasoning", "id": "rs_1", "encrypted_content": "chiffre", "summary": []},
                {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "read_file", "arguments": "{\"path\":\"src/a.rs\"}"}
            ]}}),
        ]),
        2 => sse(&[
            json!({"type": "response.completed", "response": {"output": [
                {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Terminé."}]}
            ]}}),
        ]),
        3 => sse(&[
            json!({"type": "response.failed", "response": {"error": {"code": "subscription_sharing_usage_limit_exceeded"}}}),
        ]),
        // 4 : flux coupé sans response.completed
        _ => sse(&[json!({"type": "response.output_text.delta", "delta": "début"})]),
    }
}

struct Fixture {
    idp: Arc<Mutex<Idp>>,
    secrets: MemorySecrets,
    base: String,
    data: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let idp = Arc::new(Mutex::new(Idp {
        grant_plan: true,
        expires_in: 3600,
        ..Idp::default()
    }));
    let base = start_server(idp.clone());
    Fixture {
        idp,
        secrets: MemorySecrets(Arc::default()),
        base,
        data: tempfile::tempdir().unwrap(),
    }
}

impl Fixture {
    fn auth(&self) -> ChatGptAuth {
        let endpoints = Endpoints {
            authorize: format!("{}/authorize", self.base),
            token: format!("{}/token", self.base),
            jwks: format!("{}/jwks", self.base),
            discovery: format!("{}/discovery", self.base),
            issuer: self.base.clone(),
            models: format!("{}/models", self.base),
        };
        ChatGptAuth::with(self.data.path(), Box::new(self.secrets.clone()), endpoints)
    }

    /// Simule le navigateur : lit l'URL d'autorisation, puis appelle le retour local.
    fn browser(&self) -> impl Fn(&str) -> Result<()> {
        let idp = self.idp.clone();
        move |authorize: &str| {
            let url = url::Url::parse(authorize).unwrap();
            let get = |name: &str| {
                url.query_pairs()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.into_owned())
            };
            assert_eq!(get("response_type").unwrap(), "code");
            assert_eq!(get("code_challenge_method").unwrap(), "S256");
            assert_eq!(get("resource").unwrap(), "https://api.openai.com/v1");
            assert!(get("scope").unwrap().contains("chatgpt.tokens.use.direct"));
            assert!(get("ext_agent_host_id").unwrap().starts_with("urn:uuid:"));
            let redirect = get("redirect_uri").unwrap();
            assert!(redirect.starts_with("http://127.0.0.1:"));
            {
                let mut state = idp.lock().unwrap();
                state.nonce = get("nonce").unwrap();
                state.expected_challenge = get("code_challenge").unwrap();
            }
            let client = get("client_id").unwrap();
            let state = get("state").unwrap();
            std::thread::spawn(move || {
                // Une requête étrangère ne doit pas faire aboutir ni casser la connexion.
                let _ = ureq::get(&format!("{redirect}?code=pirate&state=mauvais")).call();
                let issued = if client == "dynamic_agent_client" {
                    format!("&client_id={CLIENT}")
                } else {
                    String::new()
                };
                let _ = ureq::get(&format!(
                    "{redirect}?code=bon-code&state={state}{issued}&scope=openid"
                ))
                .call();
            });
            Ok(())
        }
    }
}

fn sign_in(fx: &Fixture, auth: &mut ChatGptAuth) -> Result<()> {
    auth.sign_in(&fx.browser(), &AtomicBool::new(false))
}

fn config(fx: &Fixture) -> Config {
    Config {
        provider: Provider::ChatGptPlan,
        remote_url: format!("{}/responses", fx.base),
        remote_model: "modele-visible".into(),
        ..Config::default()
    }
}

#[test]
fn sign_in_stores_identity_and_tokens_safely() {
    let fx = fixture();
    let mut auth = fx.auth();
    assert!(!auth.is_connected());
    sign_in(&fx, &mut auth).unwrap();
    assert!(auth.is_connected());
    assert_eq!(auth.email(), "dev@example.test");
    assert_eq!(auth.access_token().unwrap(), "access-1");
    assert_eq!(fx.secrets.get().unwrap(), "refresh-1");
    assert_eq!(auth.models().unwrap(), vec!["modele-visible".to_string()]);
    assert!(auth.take_first_welcome().unwrap());
    assert!(!auth.take_first_welcome().unwrap());

    // Aucun jeton n'est écrit dans le fichier d'état.
    let saved = std::fs::read_to_string(fx.data.path().join("chatgpt.json")).unwrap();
    assert!(saved.contains(CLIENT));
    assert!(
        !saved.contains("access-") && !saved.contains("refresh-"),
        "{saved}"
    );

    let form = fx.idp.lock().unwrap().token_forms[0].clone();
    assert_eq!(form_field(&form, "client_id").unwrap(), CLIENT);
    assert_eq!(form_field(&form, "code").unwrap(), "bon-code");
    assert!(form_field(&form, "client_secret").is_none());
}

#[test]
fn bad_identity_tokens_are_rejected_and_nothing_is_stored() {
    for tamper in ["nonce", "audience", "issuer", "expired", "forged"] {
        let fx = fixture();
        fx.idp.lock().unwrap().tamper = Some(tamper);
        let mut auth = fx.auth();
        assert!(sign_in(&fx, &mut auth).is_err(), "{tamper}");
        assert!(fx.secrets.get().is_none(), "{tamper}");
        assert!(!auth.is_connected(), "{tamper}");
    }
}

#[test]
fn refused_code_explains_itself_and_keeps_the_registration_for_the_retry() {
    let fx = fixture();
    fx.idp.lock().unwrap().exchange_refused = true;
    let mut auth = fx.auth();
    let error = sign_in(&fx, &mut auth).unwrap_err().to_string();
    assert!(error.contains("invalid_grant"), "{error}");
    assert!(
        error.contains("A required permission is unavailable"),
        "{error}"
    );
    assert!(error.contains("Réessayez"), "{error}");
    assert!(fx.secrets.get().is_none());
    assert!(!auth.is_connected());

    // La nouvelle tentative réutilise le client enregistré et aboutit.
    fx.idp.lock().unwrap().exchange_refused = false;
    let captured = Arc::new(Mutex::new(String::new()));
    let inner = fx.browser();
    let seen = captured.clone();
    let open = move |url: &str| {
        *seen.lock().unwrap() = url.to_string();
        inner(url)
    };
    auth.sign_in(&open, &AtomicBool::new(false)).unwrap();
    assert!(auth.is_connected());
    let url = url::Url::parse(&captured.lock().unwrap()).unwrap();
    let client = url
        .query_pairs()
        .find(|(k, _)| k == "client_id")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(client, CLIENT);
}

#[test]
fn plan_scope_is_required() {
    let fx = fixture();
    fx.idp.lock().unwrap().grant_plan = false;
    let mut auth = fx.auth();
    let error = sign_in(&fx, &mut auth).unwrap_err().to_string();
    assert!(error.contains("forfait"), "{error}");
    assert!(fx.secrets.get().is_none());
}

#[test]
fn second_sign_in_reuses_the_registered_client_and_host() {
    let fx = fixture();
    let mut auth = fx.auth();
    sign_in(&fx, &mut auth).unwrap();
    let first = std::fs::read_to_string(fx.data.path().join("chatgpt.json")).unwrap();

    let captured = Arc::new(Mutex::new(String::new()));
    let inner = fx.browser();
    let seen = captured.clone();
    let open = move |url: &str| {
        *seen.lock().unwrap() = url.to_string();
        inner(url)
    };
    let mut again = fx.auth();
    again.sign_in(&open, &AtomicBool::new(false)).unwrap();
    let url = url::Url::parse(&captured.lock().unwrap()).unwrap();
    let get = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    assert_eq!(get("client_id").unwrap(), CLIENT);
    assert!(get("agent_name_hint").is_none());
    assert!(first.contains(&get("ext_agent_host_id").unwrap()));
}

#[test]
fn other_account_is_rejected_then_registers_again() {
    let fx = fixture();
    let mut auth = fx.auth();
    sign_in(&fx, &mut auth).unwrap();
    fx.idp.lock().unwrap().tamper = Some("subject");
    let mut again = fx.auth();
    let error = sign_in(&fx, &mut again).unwrap_err().to_string();
    assert!(error.contains("compte"), "{error}");
    let saved = std::fs::read_to_string(fx.data.path().join("chatgpt.json")).unwrap();
    assert!(!saved.contains(CLIENT), "{saved}");
}

#[test]
fn cancel_stops_waiting_without_storing_anything() {
    let fx = fixture();
    let mut auth = fx.auth();
    let cancel = AtomicBool::new(true);
    let error = auth
        .sign_in(&|_: &str| Ok(()), &cancel)
        .unwrap_err()
        .to_string();
    assert!(error.contains("annulée"), "{error}");
    assert!(!auth.is_connected());
}

#[test]
fn expired_access_token_is_refreshed_and_rotated() {
    let fx = fixture();
    fx.idp.lock().unwrap().expires_in = 10; // sous la marge de renouvellement
    let mut auth = fx.auth();
    sign_in(&fx, &mut auth).unwrap();
    assert_eq!(auth.access_token().unwrap(), "access-2");
    assert_eq!(fx.secrets.get().unwrap(), "refresh-2");
    let form = fx.idp.lock().unwrap().token_forms[1].clone();
    assert_eq!(form_field(&form, "grant_type").unwrap(), "refresh_token");
    assert_eq!(form_field(&form, "refresh_token").unwrap(), "refresh-1");
    assert_eq!(form_field(&form, "client_id").unwrap(), CLIENT);
    assert!(form_field(&form, "scope").is_none());
}

#[test]
fn terminal_refresh_error_disconnects_but_keeps_registration() {
    let fx = fixture();
    fx.idp.lock().unwrap().expires_in = 10;
    let mut auth = fx.auth();
    sign_in(&fx, &mut auth).unwrap();
    fx.idp.lock().unwrap().refresh_error = Some("refresh_token_reused");
    let error = auth.access_token().unwrap_err().to_string();
    assert!(error.contains("reconnectez"), "{error}");
    assert!(fx.secrets.get().is_none());
    let saved = std::fs::read_to_string(fx.data.path().join("chatgpt.json")).unwrap();
    assert!(saved.contains(CLIENT));
}

#[test]
fn temporary_refresh_failure_keeps_the_connection() {
    let fx = fixture();
    fx.idp.lock().unwrap().expires_in = 10;
    let mut auth = fx.auth();
    sign_in(&fx, &mut auth).unwrap();
    fx.idp.lock().unwrap().refresh_error = Some("server_error");
    assert!(auth.access_token().is_err());
    assert_eq!(fx.secrets.get().unwrap(), "refresh-1");
}

#[test]
fn tool_loop_follows_the_stateless_responses_protocol() {
    let fx = fixture();
    let mut auth = fx.auth();
    sign_in(&fx, &mut auth).unwrap();
    let mut remote = RemoteAi::new(&config(&fx)).unwrap();
    remote.push_user("Corrige zq_abc123");

    let turn = remote.step(&mut auth).unwrap();
    assert_eq!(turn.calls.len(), 1);
    assert_eq!(turn.calls[0].id, "call_1");
    assert_eq!(turn.calls[0].input["path"], json!("src/a.rs"));
    remote.push_results(&[ToolOutcome {
        id: "call_1".into(),
        content: "contenu".into(),
        is_error: false,
    }]);

    let turn = remote.step(&mut auth).unwrap();
    assert_eq!(turn.text, "Terminé.");
    assert!(turn.calls.is_empty());

    let requests = fx.idp.lock().unwrap().responses.clone();
    let first = &requests[0];
    assert_eq!(first["store"], json!(false));
    assert_eq!(first["stream"], json!(true));
    assert_eq!(first["model"], json!("modele-visible"));
    assert!(first["instructions"]
        .as_str()
        .unwrap()
        .contains("placeholders"));
    assert_eq!(first["tools"][0]["type"], json!("function"));
    assert!(first["tools"][0].get("input_schema").is_none());
    for forbidden in [
        "previous_response_id",
        "max_output_tokens",
        "temperature",
        "metadata",
        "user",
    ] {
        assert!(first.get(forbidden).is_none(), "{forbidden}");
    }

    // Le second tour rejoue tout : le raisonnement chiffré reste intact et précède le résultat.
    let input = requests[1]["input"].as_array().unwrap();
    assert_eq!(input[0]["role"], json!("user"));
    assert_eq!(input[1]["encrypted_content"], json!("chiffre"));
    assert_eq!(input[2]["call_id"], json!("call_1"));
    assert_eq!(input[3]["type"], json!("function_call_output"));
    assert_eq!(input[3]["call_id"], json!("call_1"));
    assert_eq!(input[3]["output"], json!("contenu"));

    // Limite d'usage, puis flux coupé : deux erreurs claires, jamais un faux succès.
    let limit = remote.step(&mut auth).unwrap_err().to_string();
    assert!(limit.contains("Manage usage"), "{limit}");
    let cut = remote.step(&mut auth).unwrap_err().to_string();
    assert!(cut.contains("interrompu"), "{cut}");
}

#[test]
fn chatgpt_mode_needs_no_api_key() {
    let fx = fixture();
    assert!(RemoteAi::new(&config(&fx)).is_ok());
    let without_key = Config {
        provider: Provider::Anthropic,
        ..Config::default()
    };
    assert!(RemoteAi::new(&without_key).is_err());
}
