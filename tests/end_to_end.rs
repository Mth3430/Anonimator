//! Parcours complet avec de faux serveurs Ollama et Anthropic sur la boucle locale.
//! Le test clé : on inspecte octet par octet ce que le serveur « en ligne » a reçu.

use anonimator::agent::{spawn_worker, Approval, Command, Event, RemoteLine, Sink};
use anonimator::config::Config;
use regex::Regex;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SECRET_SOURCE: &str = r#"// Marge négociée avec Contoso, ne pas diffuser
pub struct ContosoLedger { private_margin: f32 }

pub fn compute_private_margin(gross_amount: f32) -> f32 {
    let contact = "marie.curie@contoso.example";
    let vault_pwd = "918273";
    println!("{} {}", contact, vault_pwd);
    gross_amount * 0.37
}
"#;

const SECRETS: &[&str] = &[
    "Contoso",
    "contoso",
    "ContosoLedger",
    "private_margin",
    "compute_private_margin",
    "gross_amount",
    "marie.curie",
    "Marge",
    "billing_core",
    "TOP_SECRET_ENV",
    "Projet interne",
    "Dupond",
    "918273",
    "vault_pwd",
];

type Script = dyn Fn(usize, &Value) -> Value + Send + Sync;

#[derive(Default)]
struct Traffic {
    local: Vec<String>,
    remote_bodies: Vec<String>,
    remote_headers: Vec<String>,
}

/// Serveur HTTP minimal : /api/chat répond comme Ollama, le reste suit le script distant.
fn start_server(local_plan: Value, script: Arc<Script>) -> (String, Arc<Mutex<Traffic>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let traffic = Arc::new(Mutex::new(Traffic::default()));
    let shared = traffic.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let (head, body) = read_request(&mut stream);
            let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let reply = if head.starts_with("POST /api/chat") {
                shared.lock().unwrap().local.push(body.clone());
                // La demande de plan impose un JSON, le résumé non.
                let content = if parsed.get("format").is_some() {
                    local_plan.to_string()
                } else {
                    "Résumé local terminé.".to_string()
                };
                json!({"message": {"role": "assistant", "content": content}})
            } else {
                let mut t = shared.lock().unwrap();
                t.remote_bodies.push(body.clone());
                t.remote_headers.push(head.clone());
                let index = t.remote_bodies.len() - 1;
                drop(t);
                script(index, &parsed)
            };
            let text = reply.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                text.len(),
                text
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (base, traffic)
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

fn make_project(root: &Path) {
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/billing_core.rs"), SECRET_SOURCE).unwrap();
    std::fs::write(root.join(".env"), "TOP_SECRET_ENV=1\n").unwrap();
    std::fs::write(root.join("README.md"), "Projet interne pour Contoso\n").unwrap();
}

fn tool_use(id: &str, name: &str, input: Value) -> Value {
    json!({
        "content": [{"type": "tool_use", "id": id, "name": name, "input": input}],
        "stop_reason": "tool_use"
    })
}

fn last_tool_result(request: &Value) -> String {
    let messages = request["messages"].as_array().unwrap();
    messages.last().unwrap()["content"][0]["content"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

struct Harness {
    tx: Sender<Command>,
    events: Receiver<Event>,
    _project: tempfile::TempDir,
    _data: tempfile::TempDir,
    root: std::path::PathBuf,
}

fn start(base: &str, project_setup: bool, require_approval: bool) -> Harness {
    let project = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    if project_setup {
        make_project(project.path());
    }
    let config = Config {
        ollama_url: base.to_string(),
        remote_url: format!("{base}/v1/messages"),
        api_key: "test-key".into(),
        require_approval,
        custom_terms: "Contoso".into(),
        ..Config::default()
    };
    let (event_tx, events) = channel();
    let event_tx = Mutex::new(event_tx);
    let sink: Sink = Arc::new(move |event| {
        let _ = event_tx.lock().unwrap().send(event);
    });
    let tx = spawn_worker(config, data.path().to_path_buf(), sink);
    tx.send(Command::OpenWorkspace(project.path().to_path_buf()))
        .unwrap();
    let root = project.path().to_path_buf();
    Harness {
        tx,
        events,
        _project: project,
        _data: data,
        root,
    }
}

/// Lit les événements jusqu'à la fin de la commande en cours.
fn drain(h: &Harness, mut on_ask: impl FnMut(&str)) -> Vec<Event> {
    let mut seen = Vec::new();
    let mut started = false;
    loop {
        let event = h
            .events
            .recv_timeout(Duration::from_secs(30))
            .expect("le worker ne répond plus");
        match &event {
            Event::Busy(true) => started = true,
            Event::Busy(false) if started => {
                seen.push(event);
                return seen;
            }
            Event::AskApproval { text, .. } => on_ask(text),
            _ => {}
        }
        seen.push(event);
    }
}

fn delegate_plan() -> Value {
    json!({
        "action": "delegate",
        "instruction": "Rename gross_amount handling for Contoso in compute_private_margin and add a helper.",
        "sensitive_terms": ["Dupond"]
    })
}

/// Script d'une IA en ligne crédible, qui ne connaît que ce qu'on lui a montré.
fn working_remote() -> Arc<Script> {
    let path_re = Regex::new(r"\S*zq_[a-z0-9]{6}\.rs").unwrap();
    let fn_re = Regex::new(r"pub fn (zq_[a-z0-9]{6})").unwrap();
    let state: Arc<Mutex<(String, String)>> = Arc::default();
    Arc::new(move |index, request| match index {
        0 => tool_use("t1", "list_files", json!({})),
        1 => {
            let listing = last_tool_result(request);
            let path = path_re
                .find(&listing)
                .expect("chemin masqué attendu")
                .as_str()
                .to_string();
            state.lock().unwrap().0 = path.clone();
            tool_use("t2", "read_file", json!({"path": path}))
        }
        2 => {
            let source = last_tool_result(request);
            let name = fn_re.captures(&source).expect("fonction masquée attendue")[1].to_string();
            let mut s = state.lock().unwrap();
            s.1 = name.clone();
            json!({"content": [
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "tool_use", "id": "t3", "name": "edit_file", "input": {
                    "path": s.0,
                    "old_text": format!("pub fn {name}"),
                    "new_text": format!("#[inline]\npub fn {name}"),
                }},
                {"type": "tool_use", "id": "t4", "name": "write_file", "input": {
                    "path": "src/helper_module.rs",
                    "content": format!("pub fn wrap() {{ super::{name}(1.0); }}\n"),
                }},
                {"type": "tool_use", "id": "t5", "name": "read_file", "input": {"path": ".env"}},
                {"type": "tool_use", "id": "t6", "name": "read_file", "input": {"path": "../../etc/passwd"}},
            ], "stop_reason": "tool_use"})
        }
        _ => {
            let name = state.lock().unwrap().1.clone();
            json!({"content": [{"type": "text", "text": format!("Done: added inline to {name}.")}], "stop_reason": "end_turn"})
        }
    })
}

#[test]
fn nothing_sensitive_reaches_remote_and_edits_come_back_real() {
    let (base, traffic) = start_server(delegate_plan(), working_remote());
    let h = start(&base, true, true);
    drain(&h, |_| {});

    h.tx.send(Command::Send(
        "Pour Contoso (contact M. Dupond), améliore la marge.".into(),
    ))
    .unwrap();
    let tx = h.tx.clone();
    let mut approvals = Vec::new();
    let events = drain(&h, |text| {
        approvals.push(text.to_string());
        tx.send(Command::Answer(Approval::Once)).unwrap();
    });

    let errors: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, Event::Error(_)))
        .collect();
    assert!(errors.is_empty(), "{errors:?}");

    let t = traffic.lock().unwrap();
    assert_eq!(t.remote_bodies.len(), 4);
    for (index, body) in t.remote_bodies.iter().enumerate() {
        for secret in SECRETS {
            assert!(
                !body.contains(secret),
                "« {secret} » a fuité dans la requête {index} :\n{body}"
            );
        }
    }
    let username = std::env::var("USERNAME").unwrap_or_default();
    if username.len() >= 3 {
        assert!(!t.remote_bodies[0].contains(&username));
    }
    // Ce qui a été validé est bien ce qui part.
    assert!(approvals
        .iter()
        .all(|a| !SECRETS.iter().any(|s| a.contains(s))));
    assert!(approvals.len() >= 4);

    // Protocole Anthropic : version, clé, bêta et bloc de réflexion rejoué tel quel.
    assert!(t.remote_headers[0]
        .to_lowercase()
        .contains("anthropic-version: 2026-10-21"));
    assert!(t.remote_headers[0]
        .to_lowercase()
        .contains("x-api-key: test-key"));
    let last: Value = serde_json::from_str(t.remote_bodies.last().unwrap()).unwrap();
    assert_eq!(last["fallbacks"], json!("default"));
    let replayed = &last["messages"].as_array().unwrap();
    assert!(replayed
        .iter()
        .any(|m| m["content"][0]["type"] == json!("thinking")));
    let results = replayed.last().unwrap()["content"].as_array().unwrap();
    assert_eq!(results.len(), 4, "tous les résultats dans un seul message");
    assert_eq!(results[2]["is_error"], json!(true), ".env refusé");
    assert_eq!(results[3]["is_error"], json!(true), "traversée refusée");

    // L'IA locale, elle, voit les vrais noms dans son compte rendu.
    let summary_request = t.local.last().unwrap();
    assert!(
        summary_request.contains("compute_private_margin"),
        "{summary_request}"
    );
    drop(t);

    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Assistant(s) if s.contains("Résumé local"))));

    // La colonne de l'IA en ligne affiche ses réponses et ses actions avec les vrais noms.
    let lines: Vec<&RemoteLine> = events
        .iter()
        .filter_map(|e| {
            if let Event::Remote(line) = e {
                Some(line)
            } else {
                None
            }
        })
        .collect();
    assert!(lines.iter().any(|l| matches!(l, RemoteLine::Text(t) if t == "Done: added inline to compute_private_margin.")), "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| matches!(l, RemoteLine::Activity(a) if a == "Lit src/billing_core.rs")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| matches!(l, RemoteLine::Activity(a) if a.starts_with("Refusé"))),
        "{lines:?}"
    );

    // Le coffre signale le secret sans jamais citer sa valeur.
    let secrets: Vec<&String> = events
        .iter()
        .filter_map(|e| {
            if let Event::WorkspaceReady { secrets, .. } = e {
                Some(secrets)
            } else {
                None
            }
        })
        .flatten()
        .collect();
    assert!(secrets.iter().all(|s| !s.contains("918273")), "{secrets:?}");

    // Rien sur le disque avant validation.
    let real = h.root.join("src/billing_core.rs");
    assert_eq!(std::fs::read_to_string(&real).unwrap(), SECRET_SOURCE);
    assert!(!h.root.join("src/helper_module.rs").exists());

    h.tx.send(Command::ApplyChanges).unwrap();
    drain(&h, |_| {});

    // Le fichier revient avec ses vrais noms, commentaires et chaînes, et seule l'édition change.
    let expected = SECRET_SOURCE.replace("pub fn compute", "#[inline]\npub fn compute");
    assert_eq!(std::fs::read_to_string(&real).unwrap(), expected);
    let helper = std::fs::read_to_string(h.root.join("src/helper_module.rs")).unwrap();
    assert_eq!(
        helper,
        "pub fn wrap() { super::compute_private_margin(1.0); }\n"
    );
}

#[test]
fn refusing_approval_sends_nothing() {
    let (base, traffic) = start_server(delegate_plan(), working_remote());
    let h = start(&base, true, true);
    drain(&h, |_| {});
    h.tx.send(Command::Send("Fais le travail".into())).unwrap();
    let tx = h.tx.clone();
    drain(&h, |_| tx.send(Command::Answer(Approval::Refuse)).unwrap());
    assert!(traffic.lock().unwrap().remote_bodies.is_empty());
}

#[test]
fn local_reply_never_touches_remote() {
    let plan = json!({"action": "reply", "reply": "Bonjour !"});
    let (base, traffic) = start_server(plan, working_remote());
    let h = start(&base, true, false);
    drain(&h, |_| {});
    h.tx.send(Command::Send("Salut".into())).unwrap();
    let events = drain(&h, |_| {});
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Assistant(s) if s == "Bonjour !")));
    assert!(traffic.lock().unwrap().remote_bodies.is_empty());
}

#[test]
fn local_ai_down_fails_closed() {
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_url = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    let (remote_base, traffic) = start_server(json!({}), working_remote());
    let project = tempfile::tempdir().unwrap();
    make_project(project.path());
    let data = tempfile::tempdir().unwrap();
    let config = Config {
        ollama_url: dead_url,
        remote_url: format!("{remote_base}/v1/messages"),
        api_key: "k".into(),
        ..Config::default()
    };
    let (event_tx, events) = channel();
    let event_tx = Mutex::new(event_tx);
    let sink: Sink = Arc::new(move |e| {
        let _ = event_tx.lock().unwrap().send(e);
    });
    let tx = spawn_worker(config, data.path().to_path_buf(), sink);
    tx.send(Command::OpenWorkspace(project.path().to_path_buf()))
        .unwrap();
    tx.send(Command::Send("Fais le travail".into())).unwrap();
    let mut got_error = false;
    while let Ok(event) = events.recv_timeout(Duration::from_secs(5)) {
        if let Event::Error(message) = event {
            got_error = message.contains("injoignable");
            break;
        }
    }
    assert!(got_error);
    assert!(traffic.lock().unwrap().remote_bodies.is_empty());
}

#[test]
fn error_messages_do_not_echo_real_names() {
    // L'IA en ligne cible un fichier existant masqué avec un mauvais old_text :
    // le message d'erreur ne doit révéler aucun vrai nom.
    let path_re = Regex::new(r"\S*zq_[a-z0-9]{6}\.rs").unwrap();
    let script: Arc<Script> = Arc::new(move |index, request| match index {
        0 => tool_use("t1", "list_files", json!({})),
        1 => {
            let listing = last_tool_result(request);
            let dir = path_re
                .find(&listing)
                .unwrap()
                .as_str()
                .rsplit_once('/')
                .unwrap()
                .0
                .to_string();
            // Le dossier réel existe mais n'est pas un fichier : l'erreur cite le vrai chemin.
            tool_use(
                "t2",
                "read_file",
                json!({"path": format!("{dir}/absent.rs")}),
            )
        }
        _ => json!({"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}),
    });
    let (base, traffic) = start_server(delegate_plan(), script);
    let h = start(&base, true, false);
    drain(&h, |_| {});
    h.tx.send(Command::Send("Fais le travail".into())).unwrap();
    drain(&h, |_| {});
    let t = traffic.lock().unwrap();
    assert_eq!(t.remote_bodies.len(), 3);
    for secret in SECRETS {
        assert!(!t.remote_bodies[2].contains(secret), "{secret}");
    }
}
