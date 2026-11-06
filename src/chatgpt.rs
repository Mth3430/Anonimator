//! Connexion « Sign in with ChatGPT » pour une application locale, d'après
//! https://developers.openai.com/siwc/token-sharing-open-source/sign-in
//!
//! Le jeton de renouvellement va dans le gestionnaire d'identifiants de l'OS.
//! Le jeton d'accès, valable une heure, reste en mémoire.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const REGISTRATION_CLIENT: &str = "dynamic_agent_client";
const APP_NAME: &str = "Anonimator";
const RESOURCE: &str = "https://api.openai.com/v1";
const PLAN_SCOPE: &str = "chatgpt.tokens.use.direct";
const SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const CALLBACK_PATH: &str = "/auth/callback";
const PREFERRED_PORT: u16 = 1455;
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const REFRESH_MARGIN: Duration = Duration::from_secs(60);
const TERMINAL_REFRESH_ERRORS: &[&str] = &[
    "invalid_grant",
    "invalid_refresh_token",
    "token_expired",
    "refresh_token_expired",
    "refresh_token_invalidated",
    "refresh_token_reused",
];

pub const USAGE_URL: &str = "https://chatgpt.com/#settings";

#[derive(Clone, Debug)]
pub struct Endpoints {
    pub authorize: String,
    pub token: String,
    pub jwks: String,
    pub discovery: String,
    pub issuer: String,
    pub models: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            authorize: "https://auth.openai.com/api/accounts/authorize".into(),
            token: "https://auth.openai.com/api/accounts/oauth/token".into(),
            jwks: "https://auth.openai.com/.well-known/jwks.json".into(),
            discovery: "https://auth.openai.com/.well-known/openid-configuration".into(),
            issuer: "https://auth.openai.com".into(),
            models: "https://api.openai.com/v1/models".into(),
        }
    }
}

pub trait Secrets: Send {
    fn get(&self) -> Option<String>;
    fn set(&mut self, value: &str) -> Result<()>;
    fn clear(&mut self);
}

pub struct KeyringSecrets;

impl KeyringSecrets {
    fn entry() -> keyring::Result<keyring::Entry> {
        keyring::Entry::new("anonimator", "chatgpt-refresh-token")
    }
}

impl Secrets for KeyringSecrets {
    fn get(&self) -> Option<String> {
        Self::entry().and_then(|entry| entry.get_password()).ok()
    }

    fn set(&mut self, value: &str) -> Result<()> {
        Self::entry()
            .and_then(|entry| entry.set_password(value))
            .context("enregistrement de la connexion dans le gestionnaire d'identifiants")
    }

    fn clear(&mut self) {
        if let Ok(entry) = Self::entry() {
            let _ = entry.delete_credential();
        }
    }
}

/// Ce qui survit aux redémarrages hors du coffre de l'OS. Aucun jeton ici.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct State {
    host_id: String,
    client_id: String,
    subject: String,
    email: String,
    welcomed: bool,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: u64,
    scope: Option<String>,
}

pub struct ChatGptAuth {
    path: PathBuf,
    state: State,
    secrets: Box<dyn Secrets>,
    endpoints: Endpoints,
    access: Option<(String, Instant)>,
}

impl ChatGptAuth {
    pub fn load(data_dir: &std::path::Path) -> Self {
        Self::with(data_dir, Box::new(KeyringSecrets), Endpoints::default())
    }

    pub fn with(
        data_dir: &std::path::Path,
        secrets: Box<dyn Secrets>,
        endpoints: Endpoints,
    ) -> Self {
        let path = data_dir.join("chatgpt.json");
        let state = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        ChatGptAuth {
            path,
            state,
            secrets,
            endpoints,
            access: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.access.is_some() || self.secrets.get().is_some()
    }

    pub fn email(&self) -> &str {
        &self.state.email
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, serde_json::to_vec_pretty(&self.state)?)
            .context("écriture de chatgpt.json")
    }

    /// Vrai une seule fois : à la première connexion, l'interface explique l'usage du forfait.
    pub fn take_first_welcome(&mut self) -> Result<bool> {
        if self.state.welcomed {
            return Ok(false);
        }
        self.state.welcomed = true;
        self.save()?;
        Ok(true)
    }

    /// Connexion complète. `open` ouvre le navigateur, `cancel` permet d'abandonner l'attente.
    pub fn sign_in(
        &mut self,
        open: &dyn Fn(&str) -> Result<()>,
        cancel: &AtomicBool,
    ) -> Result<()> {
        // L'écoute démarre avant l'ouverture du navigateur, comme l'exige OpenAI.
        let listener = TcpListener::bind(("127.0.0.1", PREFERRED_PORT))
            .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))
            .context("impossible d'ouvrir le port local de connexion")?;
        let port = listener.local_addr()?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");

        if self.state.host_id.is_empty() {
            self.state.host_id = new_host_id();
            self.save()?;
        }
        let state = random_token();
        let nonce = random_token();
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let authorize = self.authorize_url(&redirect_uri, &state, &nonce, &challenge)?;
        open(&authorize)?;

        let callback = wait_for_callback(&listener, port, &state, cancel)?;
        if let Some(error) = single(&callback, "error")? {
            if error == "access_denied" {
                bail!("connexion refusée : l'usage du forfait ChatGPT n'a pas été autorisé pour cette application");
            }
            bail!("connexion refusée par ChatGPT : {error}");
        }
        let code =
            single(&callback, "code")?.ok_or_else(|| anyhow!("réponse de connexion sans code"))?;
        let client_id = self.resolve_client_id(single(&callback, "client_id")?)?;
        // Enregistré avant l'échange : une nouvelle tentative ne créera pas un second client.
        self.state.client_id = client_id.clone();
        self.save()?;

        let tokens = self.post_token(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client_id),
            ("code", code),
            ("code_verifier", &verifier),
            ("redirect_uri", &redirect_uri),
            ("resource", RESOURCE),
        ]);
        let tokens = tokens.map_err(|error| {
            let detail = format!("{error:#}");
            // OpenAI demande de jeter ce code et de recommencer avec le même client, déjà enregistré.
            if detail.contains("invalid_grant") {
                anyhow!(
                    "ChatGPT a refusé la connexion ({detail}). Réessayez une fois. Si l'erreur revient, \
                     votre compte n'a peut-être pas accès à l'usage du forfait dans les applications : \
                     il faut en général un forfait Plus ou Pro sur un compte personnel."
                )
            } else {
                error
            }
        })?;
        let id_token = tokens
            .id_token
            .as_deref()
            .ok_or_else(|| anyhow!("réponse de connexion sans identité"))?;
        let claims = self.verify_id_token(id_token, &client_id, Some(&nonce))?;
        let subject = claims["sub"].as_str().unwrap_or_default().to_string();
        if !self.state.subject.is_empty() && self.state.subject != subject {
            // L'enregistrement est lié à un compte : on repart de zéro pour la prochaine tentative.
            self.state.client_id.clear();
            self.state.subject.clear();
            self.save()?;
            bail!("ce compte ChatGPT n'est pas celui utilisé précédemment : cliquez à nouveau pour l'enregistrer");
        }
        let granted = tokens
            .scope
            .as_deref()
            .or(single(&callback, "scope")?)
            .unwrap_or_default();
        if !granted.split_whitespace().any(|scope| scope == PLAN_SCOPE) {
            bail!("l'usage du forfait n'est pas activé pour ce compte ChatGPT");
        }
        let refresh = tokens
            .refresh_token
            .as_deref()
            .ok_or_else(|| anyhow!("réponse de connexion sans jeton de renouvellement"))?;
        self.secrets.set(refresh)?;
        self.access = Some((tokens.access_token.clone(), expiry(tokens.expires_in)));
        self.state.subject = subject;
        self.state.email = claims["email"].as_str().unwrap_or_default().to_string();
        self.save()
    }

    fn authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        challenge: &str,
    ) -> Result<String> {
        let registered = !self.state.client_id.is_empty();
        let client_id = if registered {
            self.state.client_id.as_str()
        } else {
            REGISTRATION_CLIENT
        };
        let mut params = vec![
            ("client_id", client_id),
            ("ext_agent_host_id", self.state.host_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", redirect_uri),
            ("scope", SCOPES),
            ("resource", RESOURCE),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge_method", "S256"),
            ("code_challenge", challenge),
        ];
        if !registered {
            params.push(("agent_name_hint", APP_NAME));
        }
        if !self.state.email.is_empty() {
            params.push(("login_hint", self.state.email.as_str()));
        }
        Ok(url::Url::parse_with_params(&self.endpoints.authorize, &params)?.into())
    }

    fn resolve_client_id(&self, from_callback: Option<&str>) -> Result<String> {
        let saved = self.state.client_id.as_str();
        match from_callback {
            Some(issued) => {
                let well_formed = !issued.is_empty()
                    && issued.len() <= 200
                    && issued
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                if !well_formed || issued == REGISTRATION_CLIENT {
                    bail!("identifiant d'application invalide dans la réponse de connexion");
                }
                if !saved.is_empty() && saved != issued {
                    bail!("identifiant d'application inattendu dans la réponse de connexion");
                }
                Ok(issued.to_string())
            }
            None if !saved.is_empty() => Ok(saved.to_string()),
            None => bail!("enregistrement incomplet : réessayez la connexion"),
        }
    }

    /// Jeton d'accès valide, renouvelé si nécessaire. Le worker unique sérialise les renouvellements.
    pub fn access_token(&mut self) -> Result<String> {
        if let Some((token, expires)) = &self.access {
            if *expires > Instant::now() + REFRESH_MARGIN {
                return Ok(token.clone());
            }
        }
        let refresh = self
            .secrets
            .get()
            .ok_or_else(|| anyhow!("connectez-vous d'abord à ChatGPT"))?;
        let client_id = self.state.client_id.clone();
        let tokens = match self.post_token(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", &refresh),
            ("resource", RESOURCE),
        ]) {
            Ok(tokens) => tokens,
            Err(error) => {
                let message = format!("{error:#}");
                if TERMINAL_REFRESH_ERRORS
                    .iter()
                    .any(|code| message.contains(code))
                {
                    self.secrets.clear();
                    self.access = None;
                    bail!("la connexion à ChatGPT a expiré : reconnectez-vous");
                }
                // Une panne temporaire ne doit pas effacer la connexion.
                return Err(error);
            }
        };
        if let Some(rotated) = tokens.refresh_token.as_deref() {
            self.secrets.set(rotated)?;
        }
        if let Some(id_token) = tokens.id_token.as_deref() {
            let claims = self.verify_id_token(id_token, &client_id, None)?;
            if claims["sub"].as_str() != Some(self.state.subject.as_str()) {
                bail!("le renouvellement a renvoyé un autre compte ChatGPT");
            }
        }
        self.access = Some((tokens.access_token.clone(), expiry(tokens.expires_in)));
        Ok(tokens.access_token)
    }

    pub fn models(&mut self) -> Result<Vec<String>> {
        let token = self.access_token()?;
        let body: Value = ureq::get(&self.endpoints.models)
            .set("Authorization", &format!("Bearer {token}"))
            .timeout(Duration::from_secs(20))
            .call()
            .map_err(|error| anyhow!("liste des modèles indisponible : {}", brief(error)))?
            .into_json()?;
        Ok(body["models"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|model| model["visibility"].as_str() == Some("list"))
            .filter_map(|model| model["slug"].as_str().map(str::to_string))
            .collect())
    }

    /// Révoque la session. L'enregistrement est conservé pour la prochaine connexion.
    /// Renvoie un avertissement si la révocation distante n'a pas pu être confirmée.
    pub fn sign_out(&mut self) -> Option<String> {
        let confirmed = self
            .secrets
            .get()
            .is_none_or(|refresh| self.revoke(&refresh).is_ok());
        self.secrets.clear();
        self.access = None;
        (!confirmed).then(|| {
            "Déconnecté ici, mais la révocation n'a pas pu être confirmée : vous pouvez retirer l'application dans les réglages de ChatGPT.".to_string()
        })
    }

    fn revoke(&self, refresh: &str) -> Result<()> {
        let discovery: Value = ureq::get(&self.endpoints.discovery)
            .timeout(Duration::from_secs(10))
            .call()?
            .into_json()?;
        let endpoint = discovery["revocation_endpoint"]
            .as_str()
            .ok_or_else(|| anyhow!("révocation indisponible"))?;
        ureq::post(endpoint)
            .timeout(Duration::from_secs(10))
            .send_form(&[
                ("token", refresh),
                ("token_type_hint", "refresh_token"),
                ("client_id", &self.state.client_id),
            ])?;
        Ok(())
    }

    fn post_token(&self, form: &[(&str, &str)]) -> Result<TokenResponse> {
        let response = ureq::post(&self.endpoints.token)
            .set("Accept", "application/json")
            .timeout(Duration::from_secs(30))
            .send_form(form);
        match response {
            Ok(response) => response
                .into_json()
                .context("réponse de connexion illisible"),
            Err(ureq::Error::Status(status, response)) => {
                let body: Value = response.into_json().unwrap_or(Value::Null);
                let code = body["error"]["code"]
                    .as_str()
                    .or(body["error"].as_str())
                    .or(body["code"].as_str())
                    .unwrap_or("inconnue");
                // Ces champs distinguent par exemple un code expiré d'un forfait non éligible.
                let reason = body["error_reason"].as_str();
                let description = body["error_description"]
                    .as_str()
                    .or(body["error"]["message"].as_str());
                let detail: String = [reason, description]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" : ")
                    .chars()
                    .take(300)
                    .collect();
                if detail.is_empty() {
                    bail!("erreur de connexion ChatGPT ({status}) : {code}");
                }
                bail!("erreur de connexion ChatGPT ({status}) : {code} : {detail}");
            }
            Err(error) => Err(anyhow!(
                "serveur de connexion ChatGPT injoignable : {}",
                brief(error)
            )),
        }
    }

    fn verify_id_token(&self, token: &str, client_id: &str, nonce: Option<&str>) -> Result<Value> {
        let header = jsonwebtoken::decode_header(token).context("identité ChatGPT invalide")?;
        let keys: JwkSet = ureq::get(&self.endpoints.jwks)
            .timeout(Duration::from_secs(15))
            .call()
            .map_err(|error| anyhow!("vérification de l'identité indisponible : {}", brief(error)))?
            .into_json()?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow!("identité ChatGPT invalide : clé non précisée"))?;
        let key = keys
            .find(&kid)
            .ok_or_else(|| anyhow!("identité ChatGPT invalide : clé inconnue"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 5;
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[self.endpoints.issuer.as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "iat", "sub"]);
        let decoded =
            jsonwebtoken::decode::<Value>(token, &DecodingKey::from_jwk(key)?, &validation)
                .context("identité ChatGPT invalide")?;
        let claims = decoded.claims;
        if claims["sub"].as_str().unwrap_or_default().is_empty() {
            bail!("identité ChatGPT invalide : compte absent");
        }
        if let Some(expected) = nonce {
            if claims["nonce"].as_str() != Some(expected) {
                bail!("identité ChatGPT invalide : nonce différent");
            }
        }
        let azp = claims["azp"].as_str();
        let many_audiences = claims["aud"].as_array().is_some_and(|list| list.len() > 1);
        if azp.is_some_and(|value| value != client_id) || (many_audiences && azp.is_none()) {
            bail!("identité ChatGPT invalide : destinataire différent");
        }
        Ok(claims)
    }
}

fn expiry(expires_in: u64) -> Instant {
    Instant::now() + Duration::from_secs(expires_in)
}

fn brief(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(code, _) => format!("erreur {code}"),
        ureq::Error::Transport(_) => "réseau indisponible".to_string(),
    }
}

fn single<'a>(params: &'a HashMap<String, Vec<String>>, name: &str) -> Result<Option<&'a str>> {
    match params.get(name).map(Vec::as_slice) {
        None | Some([]) => Ok(None),
        Some([value]) => Ok(Some(value)),
        Some(_) => bail!("paramètre {name} en double dans la réponse de connexion"),
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("aléa système indisponible");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn new_host_id() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("aléa système indisponible");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn wait_for_callback(
    listener: &TcpListener,
    port: u16,
    expected_state: &str,
    cancel: &AtomicBool,
) -> Result<HashMap<String, Vec<String>>> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + SIGN_IN_TIMEOUT;
    loop {
        if cancel.load(Ordering::SeqCst) {
            bail!("connexion annulée");
        }
        if Instant::now() > deadline {
            bail!("connexion expirée : réessayez");
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(params) = handle_callback(stream, port, expected_state) {
                    return Ok(params);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Une requête étrangère reçoit une erreur et ne consomme pas la connexion en cours.
fn handle_callback(
    stream: TcpStream,
    port: u16,
    expected_state: &str,
) -> Option<HashMap<String, Vec<String>>> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let mut host_ok = false;
    let expected_host = format!("127.0.0.1:{port}");
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") && value.trim() == expected_host {
                host_ok = true;
            }
        }
    }
    let mut stream = reader.into_inner();
    let target = request_line
        .strip_prefix("GET ")
        .and_then(|rest| rest.split(' ').next());
    let parsed = target.and_then(|t| url::Url::parse(&format!("http://{expected_host}{t}")).ok());
    let Some(parsed) = parsed.filter(|u| host_ok && u.path() == CALLBACK_PATH) else {
        respond(&mut stream, "404 Not Found", "Page inconnue.");
        return None;
    };
    let mut params: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in parsed.query_pairs() {
        params
            .entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    if params.get("state").map(Vec::as_slice) != Some(&[expected_state.to_string()][..]) {
        respond(
            &mut stream,
            "400 Bad Request",
            "Réponse de connexion non reconnue.",
        );
        return None;
    }
    respond(
        &mut stream,
        "200 OK",
        "Connexion terminée. Vous pouvez fermer cet onglet et revenir à Anonimator.",
    );
    Some(params)
}

fn respond(stream: &mut TcpStream, status: &str, message: &str) {
    let body =
        format!("<!doctype html><meta charset=\"utf-8\"><title>Anonimator</title><p>{message}</p>");
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}
