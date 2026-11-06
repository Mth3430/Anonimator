//! Orchestration, dans un thread dédié : l'IA locale décide, l'anonymiseur filtre,
//! l'IA en ligne travaille à travers des outils exécutés ici.

use crate::anon::{leftover_tokens, Anonymizer};
use crate::chatgpt::ChatGptAuth;
use crate::config::{Config, Provider, CHATGPT_URL};
use crate::local::{LocalAi, Plan};
use crate::remote::{RemoteAi, ToolCall, ToolOutcome};
use crate::vault::Vault;
use crate::workspace::{Change, Workspace};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

const MAX_REMOTE_TURNS: usize = 40;
const MAX_SEARCH_HITS: usize = 100;
/// En dessous, un terme signalé par l'IA locale masquerait trop de mots sans rapport.
const MIN_LOCAL_TERM_LEN: usize = 4;

pub enum Command {
    Send(String),
    Answer(Approval),
    OpenWorkspace(PathBuf),
    Configure(Config),
    ApplyChanges,
    DiscardChanges,
    ChatGptSignIn(Arc<AtomicBool>),
    ChatGptSignOut,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Approval {
    Once,
    ForThisTask,
    Refuse,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Direction {
    /// Parti vers l'IA en ligne.
    Out,
    /// Reçu de l'IA en ligne.
    In,
    /// Bloqué par l'audit, jamais envoyé.
    Blocked,
}

#[derive(Clone, Debug)]
pub enum Event {
    Assistant(String),
    Error(String),
    Status(String),
    Busy(bool),
    AskApproval {
        what: String,
        text: String,
    },
    Log {
        direction: Direction,
        label: String,
        text: String,
    },
    Changes(Vec<Change>),
    Vault(Vec<(String, String)>),
    WorkspaceReady {
        files: usize,
        names: usize,
        secrets: Vec<String>,
    },
    Remote(RemoteLine),
    /// État de la connexion ChatGPT. `selected` est le modèle retenu après une connexion.
    ChatGpt {
        email: Option<String>,
        models: Vec<String>,
        selected: Option<String>,
        welcome: bool,
    },
}

/// Ce que l'IA en ligne fait, avec les vrais noms : uniquement pour l'interface locale.
#[derive(Clone, Debug)]
pub enum RemoteLine {
    Activity(String),
    Text(String),
}

pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

pub fn spawn_worker(config: Config, data_dir: PathBuf, sink: Sink) -> Sender<Command> {
    let (tx, rx) = channel();
    std::thread::spawn(move || Session::new(config, data_dir, rx, sink).run());
    tx
}

struct Project {
    workspace: Workspace,
    anon: Anonymizer,
}

struct Session {
    config: Config,
    data_dir: PathBuf,
    rx: Receiver<Command>,
    sink: Sink,
    project: Option<Project>,
    remote: Option<RemoteAi>,
    chatgpt: ChatGptAuth,
    local_history: Vec<Value>,
    auto_approve_task: bool,
}

impl Session {
    fn new(config: Config, data_dir: PathBuf, rx: Receiver<Command>, sink: Sink) -> Self {
        Session {
            chatgpt: ChatGptAuth::load(&data_dir),
            config,
            data_dir,
            rx,
            sink,
            project: None,
            remote: None,
            local_history: Vec::new(),
            auto_approve_task: false,
        }
    }

    fn emit(&self, event: Event) {
        (self.sink)(event);
    }

    fn run(mut self) {
        if let Some(path) = self.config.workspace.clone() {
            self.open_workspace(&path);
        }
        if self.config.provider == Provider::ChatGptPlan {
            self.publish_chatgpt(None, false);
        }
        while let Ok(command) = self.rx.recv() {
            self.emit(Event::Busy(true));
            let outcome = match command {
                Command::Send(text) => self.handle_message(&text),
                Command::OpenWorkspace(path) => {
                    self.open_workspace(&path);
                    Ok(())
                }
                Command::Configure(config) => {
                    self.configure(config);
                    Ok(())
                }
                Command::ApplyChanges => self.apply_changes(),
                Command::DiscardChanges => {
                    if let Some(project) = &mut self.project {
                        project.workspace.pending.clear();
                    }
                    self.publish_changes();
                    Ok(())
                }
                Command::ChatGptSignIn(cancel) => self.chatgpt_sign_in(&cancel),
                Command::ChatGptSignOut => {
                    if let Some(warning) = self.chatgpt.sign_out() {
                        self.emit(Event::Assistant(warning));
                    }
                    self.remote = None;
                    self.emit(Event::ChatGpt {
                        email: None,
                        models: Vec::new(),
                        selected: None,
                        welcome: false,
                    });
                    Ok(())
                }
                // Une réponse hors de toute demande de validation n'a pas d'effet.
                Command::Answer(_) => Ok(()),
            };
            if let Err(error) = outcome {
                self.emit(Event::Error(format!("{error:#}")));
            }
            // Y compris après une erreur : des modifications en attente peuvent en dépendre.
            if let Some(project) = &self.project {
                if let Err(error) = project.anon.vault.save() {
                    self.emit(Event::Error(format!("{error:#}")));
                }
            }
            self.publish_vault();
            self.emit(Event::Status(String::new()));
            self.emit(Event::Busy(false));
        }
    }

    fn chatgpt_sign_in(&mut self, cancel: &AtomicBool) -> Result<()> {
        self.emit(Event::Status(
            "Terminez la connexion dans votre navigateur…".into(),
        ));
        let open = |url: &str| {
            webbrowser::open(url)
                .map(|_| ())
                .map_err(|_| anyhow!("impossible d'ouvrir le navigateur"))
        };
        self.chatgpt.sign_in(&open, cancel)?;
        self.config.provider = Provider::ChatGptPlan;
        self.config.remote_url = CHATGPT_URL.to_string();
        self.remote = None;
        let welcome = self.chatgpt.take_first_welcome()?;
        self.publish_chatgpt(Some(welcome), true);
        Ok(())
    }

    /// Publie compte et modèles. Une liste indisponible n'efface pas la connexion.
    fn publish_chatgpt(&mut self, welcome: Option<bool>, choose_model: bool) {
        if !self.chatgpt.is_connected() {
            self.emit(Event::ChatGpt {
                email: None,
                models: Vec::new(),
                selected: None,
                welcome: false,
            });
            return;
        }
        let models = match self.chatgpt.models() {
            Ok(models) => models,
            Err(error) => {
                self.emit(Event::Error(format!("{error:#}")));
                Vec::new()
            }
        };
        let current_ok = models.contains(&self.config.remote_model);
        let selected = (choose_model && !current_ok)
            .then(|| models.first().cloned())
            .flatten();
        if let Some(model) = &selected {
            self.config.remote_model = model.clone();
        }
        self.emit(Event::ChatGpt {
            email: Some(self.chatgpt.email().to_string())
                .filter(|email| !email.is_empty())
                .or(Some("compte connecté".into())),
            models,
            selected,
            welcome: welcome.unwrap_or(false),
        });
    }

    fn configure(&mut self, config: Config) {
        self.config = config;
        self.remote = None; // la conversation repart avec les nouveaux réglages
        if let Some(project) = &mut self.project {
            project.workspace.allow_prose = self.config.allow_prose;
            project.workspace.auto_detect = self.config.auto_anonymize;
            project.anon.add_deny_terms(&self.config.terms(), true);
            project.workspace.prepare(&mut project.anon);
        }
        self.publish_scan();
    }

    fn publish_scan(&self) {
        if let Some(project) = &self.project {
            self.emit(Event::WorkspaceReady {
                files: project.workspace.shareable_files().len(),
                names: project.anon.vocabulary_len(),
                secrets: project.workspace.secrets_found(),
            });
        }
    }

    fn open_workspace(&mut self, path: &Path) {
        match self.try_open(path) {
            Ok(project) => {
                self.project = Some(project);
                self.publish_scan();
                self.config.workspace = Some(path.to_path_buf());
                self.remote = None;
                self.local_history.clear();
                self.publish_changes();
                self.publish_vault();
            }
            Err(error) => self.emit(Event::Error(format!("{error:#}"))),
        }
    }

    fn try_open(&self, path: &Path) -> Result<Project> {
        let mut workspace = Workspace::open(path, self.config.allow_prose)?;
        workspace.auto_detect = self.config.auto_anonymize;
        let digest = Sha256::digest(workspace.root.to_string_lossy().as_bytes());
        let name: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
        let vault_path = self.data_dir.join("vaults").join(format!("{name}.json"));
        let mut anon = Anonymizer::new(Vault::load(&vault_path)?);
        workspace.prepare(&mut anon);
        anon.add_deny_terms(&self.config.terms(), true);
        Ok(Project { workspace, anon })
    }

    fn publish_changes(&self) {
        let changes = self
            .project
            .as_ref()
            .map(|p| p.workspace.changes())
            .unwrap_or_default();
        self.emit(Event::Changes(changes));
    }

    fn publish_vault(&self) {
        let entries = self
            .project
            .as_ref()
            .map(|p| p.anon.vault.entries())
            .unwrap_or_default();
        self.emit(Event::Vault(entries));
    }

    fn apply_changes(&mut self) -> Result<()> {
        let project = self
            .project
            .as_mut()
            .ok_or_else(|| anyhow!("aucun projet ouvert"))?;
        let count = project.workspace.apply()?;
        project.workspace.prepare(&mut project.anon);
        self.publish_changes();
        self.publish_scan();
        self.emit(Event::Assistant(format!(
            "{count} fichier(s) écrit(s) sur le disque."
        )));
        Ok(())
    }

    fn handle_message(&mut self, text: &str) -> Result<()> {
        if self.project.is_none() {
            bail!("ouvrez d'abord un dossier de projet");
        }
        let local = LocalAi::new(&self.config.ollama_url, &self.config.local_model)?;
        self.local_history
            .push(json!({"role": "user", "content": text}));
        self.emit(Event::Status("L'IA locale analyse votre message…".into()));

        let project = self.project.as_mut().expect("vérifié ci-dessus");
        project.workspace.prepare(&mut project.anon);
        let files = project.workspace.files();
        let plan = local.plan(&self.local_history, &files);
        let plan = match plan {
            Ok(plan) => plan,
            Err(error) => {
                self.local_history.pop();
                return Err(error);
            }
        };
        match plan {
            Plan::Reply(reply) => {
                self.local_history
                    .push(json!({"role": "assistant", "content": reply}));
                self.emit(Event::Assistant(reply));
                Ok(())
            }
            Plan::Delegate {
                instruction,
                sensitive_terms,
            } => {
                // Un terme inventé par le modèle ne compte pas : il doit venir du message.
                let lowered = text.to_lowercase();
                let terms: Vec<String> = sensitive_terms
                    .into_iter()
                    .filter(|t| {
                        t.chars().count() >= MIN_LOCAL_TERM_LEN
                            && lowered.contains(&t.to_lowercase())
                    })
                    .collect();
                self.project
                    .as_mut()
                    .expect("vérifié")
                    .anon
                    .add_deny_terms(&terms, false);
                self.run_remote_task(&instruction, &local)
            }
        }
    }

    fn run_remote_task(&mut self, instruction: &str, local: &LocalAi) -> Result<()> {
        self.auto_approve_task = false;
        if self.remote.is_none() {
            self.remote = Some(RemoteAi::new(&self.config)?);
        }
        let message = self.prepare_instruction(instruction)?;
        if !self.approve("Instruction pour l'IA en ligne", &message) {
            self.emit(Event::Assistant("Envoi annulé : rien n'est parti.".into()));
            return Ok(());
        }
        self.remote
            .as_mut()
            .expect("créé ci-dessus")
            .push_user(&message);
        self.log(Direction::Out, "Instruction", &message);

        let mut final_text = String::new();
        let mut finished = false;
        for _ in 0..MAX_REMOTE_TURNS {
            self.emit(Event::Status("L'IA en ligne travaille…".into()));
            let turn = self
                .remote
                .as_mut()
                .expect("créé ci-dessus")
                .step(&mut self.chatgpt)?;
            if !turn.text.is_empty() {
                self.log(Direction::In, "Réponse", &turn.text);
                final_text = turn.text.clone();
                let restored = self
                    .project
                    .as_ref()
                    .expect("vérifié par l'appelant")
                    .anon
                    .restore(&turn.text);
                self.emit(Event::Remote(RemoteLine::Text(restored)));
            }
            if turn.calls.is_empty() {
                finished = true;
                break;
            }
            let results: Vec<ToolOutcome> =
                turn.calls.iter().map(|call| self.execute(call)).collect();
            self.publish_changes();
            let preview = results
                .iter()
                .map(|r| r.content.as_str())
                .collect::<Vec<_>>()
                .join("\n---\n");
            if self.approve("Résultat d'outils pour l'IA en ligne", &preview) {
                for result in &results {
                    self.log(Direction::Out, "Résultat d'outil", &result.content);
                }
                self.remote
                    .as_mut()
                    .expect("créé ci-dessus")
                    .push_results(&results);
            } else {
                // Chaque appel d'outil doit recevoir une réponse pour que la conversation reste valide.
                let refused: Vec<ToolOutcome> = results
                    .into_iter()
                    .map(|r| ToolOutcome {
                        id: r.id,
                        content: "The user declined to share this result.".into(),
                        is_error: true,
                    })
                    .collect();
                self.remote
                    .as_mut()
                    .expect("créé ci-dessus")
                    .push_results(&refused);
                self.emit(Event::Assistant(
                    "Tâche interrompue : ce résultat n'a pas été envoyé.".into(),
                ));
                return Ok(());
            }
        }
        if !finished {
            self.emit(Event::Error(format!(
                "tâche arrêtée après {MAX_REMOTE_TURNS} échanges avec l'IA en ligne"
            )));
        }
        self.report(&final_text, local)
    }

    fn prepare_instruction(&mut self, instruction: &str) -> Result<String> {
        let project = self.project.as_mut().expect("vérifié par l'appelant");
        let masked = project.anon.prose(instruction);
        let tree: Vec<String> = project
            .workspace
            .shareable_files()
            .iter()
            .map(|path| project.anon.path(path))
            .collect();
        let message = format!("{masked}\n\nProject files:\n{}", tree.join("\n"));
        let findings = project.anon.audit(&message);
        if !findings.is_empty() {
            self.log(
                Direction::Blocked,
                "Instruction bloquée",
                &findings.join("\n"),
            );
            bail!("envoi bloqué par l'audit : {}", findings.join(", "));
        }
        Ok(message)
    }

    /// Résumé par l'IA locale, seule à voir les vrais noms.
    fn report(&mut self, final_text: &str, local: &LocalAi) -> Result<()> {
        let project = self.project.as_ref().expect("vérifié par l'appelant");
        let restored = project.anon.restore(final_text);
        let changed: Vec<String> = project.workspace.pending.keys().cloned().collect();
        let report = format!(
            "Compte rendu de l'IA en ligne :\n{restored}\n\nFichiers modifiés en attente de validation :\n{}",
            changed.join("\n")
        );
        self.emit(Event::Status("L'IA locale prépare le résumé…".into()));
        let summary = local.summarize(&report).unwrap_or(restored);
        self.local_history
            .push(json!({"role": "assistant", "content": summary}));
        self.emit(Event::Assistant(summary));
        self.publish_changes();
        Ok(())
    }

    fn approve(&mut self, what: &str, text: &str) -> bool {
        if !self.config.require_approval || self.auto_approve_task {
            return true;
        }
        self.emit(Event::AskApproval {
            what: what.to_string(),
            text: text.to_string(),
        });
        loop {
            match self.rx.recv() {
                Ok(Command::Answer(Approval::Once)) => return true,
                Ok(Command::Answer(Approval::ForThisTask)) => {
                    self.auto_approve_task = true;
                    return true;
                }
                Ok(Command::Answer(Approval::Refuse)) | Err(_) => return false,
                Ok(_) => {} // l'interface bloque les autres actions pendant la validation
            }
        }
    }

    fn log(&self, direction: Direction, label: &str, text: &str) {
        self.emit(Event::Log {
            direction,
            label: label.to_string(),
            text: text.to_string(),
        });
    }

    /// Exécute un outil et garantit que le résultat peut sortir. Un refus de l'audit
    /// remplace le contenu entier, et les détails ne sont visibles que localement.
    fn execute(&mut self, call: &ToolCall) -> ToolOutcome {
        self.log(
            Direction::In,
            &format!("Appel d'outil {}", call.name),
            &call.input.to_string(),
        );
        let activity = describe_call(
            call,
            &self.project.as_ref().expect("vérifié par l'appelant").anon,
        );
        self.emit(Event::Remote(RemoteLine::Activity(activity)));
        let project = self.project.as_mut().expect("vérifié par l'appelant");
        let result = run_tool(project, call);
        let (content, is_error) = match result {
            Ok(content) => (content, false),
            Err(error) => {
                let local = format!("{error:#}");
                (self.sink)(Event::Remote(RemoteLine::Activity(format!(
                    "Refusé : {local}"
                ))));
                // Une erreur peut citer un chemin réel : elle passe aussi par l'anonymiseur.
                (project.anon.prose(&local), true)
            }
        };
        let findings = project.anon.audit(&content);
        if findings.is_empty() {
            return ToolOutcome {
                id: call.id.clone(),
                content,
                is_error,
            };
        }
        let detail = findings.join("\n");
        self.log(Direction::Blocked, "Résultat bloqué par l'audit", &detail);
        ToolOutcome {
            id: call.id.clone(),
            content: "This result was withheld by the privacy filter.".into(),
            is_error: true,
        }
    }
}

fn describe_call(call: &ToolCall, anon: &Anonymizer) -> String {
    let field = |name: &str| anon.restore(call.input[name].as_str().unwrap_or("?"));
    match call.name.as_str() {
        "list_files" => "Liste les fichiers du projet".to_string(),
        "read_file" => format!("Lit {}", field("path")),
        "search" => format!("Cherche « {} »", field("query")),
        "write_file" => format!("Propose d'écrire {}", field("path")),
        "edit_file" => format!("Propose de modifier {}", field("path")),
        other => format!("Outil inconnu : {other}"),
    }
}

fn run_tool(project: &mut Project, call: &ToolCall) -> Result<String> {
    let Project { workspace, anon } = project;
    let text_input = |name: &str| -> Result<&str> {
        call.input[name]
            .as_str()
            .ok_or_else(|| anyhow!("missing string parameter: {name}"))
    };
    let real_path = |anon: &Anonymizer, masked: &str| anon.restore(masked).replace('\\', "/");
    match call.name.as_str() {
        "list_files" => {
            let files = workspace.shareable_files();
            Ok(files
                .iter()
                .map(|path| anon.path(path))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        "read_file" => {
            let path = real_path(anon, text_input("path")?);
            workspace.read_anonymized(&path, anon)
        }
        "search" => {
            let query = text_input("query")?;
            if query.is_empty() {
                bail!("empty query");
            }
            let mut hits = Vec::new();
            for path in workspace.shareable_files() {
                let Ok(content) = workspace.read_anonymized(&path, anon) else {
                    continue;
                };
                let shown = anon.path(&path);
                for (number, line) in content.lines().enumerate() {
                    if line.contains(query) && hits.len() < MAX_SEARCH_HITS {
                        hits.push(format!("{shown}:{}:{line}", number + 1));
                    }
                }
            }
            Ok(if hits.is_empty() {
                "No match.".to_string()
            } else {
                hits.join("\n")
            })
        }
        "write_file" => {
            let path = real_path(anon, text_input("path")?);
            let content = anon.restore(text_input("content")?);
            let warning = leftover_warning(&content);
            workspace.stage(&path, content)?;
            Ok(format!("Staged for review.{warning}"))
        }
        "edit_file" => {
            let path = real_path(anon, text_input("path")?);
            let (old, new) = (text_input("old_text")?, text_input("new_text")?);
            if old.is_empty() {
                bail!("old_text is empty");
            }
            let current = workspace.read_anonymized(&path, anon)?;
            match current.matches(old).count() {
                1 => {}
                0 => bail!("old_text not found: read the file again"),
                n => bail!("old_text occurs {n} times: include more context"),
            }
            let restored = anon.restore(&current.replacen(old, new, 1));
            let warning = leftover_warning(&restored);
            workspace.stage(&path, restored)?;
            Ok(format!("Staged for review.{warning}"))
        }
        other => bail!("unknown tool: {other}"),
    }
}

fn leftover_warning(restored: &str) -> String {
    let unknown = leftover_tokens(restored);
    if unknown.is_empty() {
        String::new()
    } else {
        format!(
            " Warning: unknown placeholders, use them exactly as you read them: {}",
            unknown.join(", ")
        )
    }
}
