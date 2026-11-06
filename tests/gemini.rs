//! Boucle d'outils au format de l'interface compatible OpenAI de Gemini, contre un faux serveur.

use anonimator::chatgpt::ChatGptAuth;
use anonimator::config::{Config, Provider, GEMINI_MODEL, GEMINI_URL};
use anonimator::remote::{RemoteAi, ToolOutcome};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Vec<(String, Value)>>>;

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
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().ok())?
                })
                .unwrap_or(0);
            while data.len() < end + 4 + length {
                let read = stream.read(&mut chunk).unwrap();
                data.extend_from_slice(&chunk[..read]);
            }
            return (head, String::from_utf8_lossy(&data[end + 4..]).to_string());
        }
        assert!(read != 0, "connexion fermée trop tôt");
    }
}

fn start_server(replies: Vec<Value>) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/v1beta/openai/chat/completions",
        listener.local_addr().unwrap()
    );
    let seen: Seen = Arc::default();
    let shared = seen.clone();
    std::thread::spawn(move || {
        for (stream, reply) in listener.incoming().zip(replies) {
            let mut stream = stream.unwrap();
            let (head, body) = read_request(&mut stream);
            shared
                .lock()
                .unwrap()
                .push((head, serde_json::from_str(&body).unwrap()));
            let text = reply.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (url, seen)
}

#[test]
fn tool_loop_keeps_gemini_thought_signatures() {
    let call = json!({
        "id": "call_1",
        "type": "function",
        "function": {"name": "read_file", "arguments": "{\"path\":\"src/a.rs\"}"},
        "extra_content": {"google": {"thought_signature": "signature-opaque"}}
    });
    let (url, seen) = start_server(vec![
        json!({"choices": [{"finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": null, "tool_calls": [call]
        }}]}),
        json!({"choices": [{"finish_reason": "stop", "message": {
            "role": "assistant", "content": "Terminé."
        }}]}),
    ]);
    let config = Config {
        provider: Provider::Gemini,
        remote_url: url,
        remote_model: GEMINI_MODEL.into(),
        api_key: "cle-test".into(),
        ..Config::default()
    };
    let data = tempfile::tempdir().unwrap();
    let mut unused_chatgpt = ChatGptAuth::load(data.path());
    let mut remote = RemoteAi::new(&config).unwrap();
    remote.push_user("Corrige zq_abc123");

    let turn = remote.step(&mut unused_chatgpt).unwrap();
    assert_eq!(turn.calls[0].id, "call_1");
    assert_eq!(turn.calls[0].input["path"], json!("src/a.rs"));
    remote.push_results(&[ToolOutcome {
        id: "call_1".into(),
        content: "contenu".into(),
        is_error: false,
    }]);
    let turn = remote.step(&mut unused_chatgpt).unwrap();
    assert_eq!(turn.text, "Terminé.");

    let requests = seen.lock().unwrap();
    assert!(requests[0]
        .0
        .to_lowercase()
        .contains("authorization: bearer cle-test"));
    let first = &requests[0].1;
    assert_eq!(first["model"], json!(GEMINI_MODEL));
    assert_eq!(first["messages"][0]["role"], json!("system"));
    let tools = first["tools"].as_array().unwrap();
    let list_files = tools
        .iter()
        .find(|t| t["function"]["name"] == "list_files")
        .unwrap();
    assert!(list_files["function"].get("parameters").is_none());
    let read_file = tools
        .iter()
        .find(|t| t["function"]["name"] == "read_file")
        .unwrap();
    assert!(read_file["function"]["parameters"]["properties"]["path"].is_object());

    // La signature de réflexion revient intacte, puis le résultat de l'outil.
    let replay = requests[1].1["messages"].as_array().unwrap();
    let assistant = &replay[2];
    assert_eq!(
        assistant["tool_calls"][0]["extra_content"]["google"]["thought_signature"],
        json!("signature-opaque")
    );
    assert_eq!(replay[3]["role"], json!("tool"));
    assert_eq!(replay[3]["tool_call_id"], json!("call_1"));
    assert_eq!(replay[3]["content"], json!("contenu"));
}

#[test]
fn official_address_is_accepted_and_a_key_is_required() {
    let without_key = Config {
        provider: Provider::Gemini,
        remote_url: GEMINI_URL.into(),
        remote_model: GEMINI_MODEL.into(),
        ..Config::default()
    };
    assert!(RemoteAi::new(&without_key).is_err());
    let with_key = Config {
        api_key: "k".into(),
        ..without_key
    };
    assert!(RemoteAi::new(&with_key).is_ok());
}
