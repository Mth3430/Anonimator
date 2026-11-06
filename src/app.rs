//! Interface. Elle n'exécute aucun travail : elle envoie des commandes au worker et affiche ses événements.

use anonimator::agent::{spawn_worker, Approval, Command, Direction, Event, RemoteLine, Sink};
use anonimator::chatgpt::{self, ChatGptAuth};
use anonimator::config::{self, Config, Provider};
use anonimator::local::LocalAi;
use anonimator::workspace::Change;
use eframe::egui::{
    self, Color32, Key, KeyboardShortcut, Modifiers, RichText, ScrollArea, TextEdit,
};
use similar::{ChangeTag, TextDiff};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

const OUT_COLOR: Color32 = Color32::from_rgb(217, 140, 40);
const IN_COLOR: Color32 = Color32::from_rgb(70, 150, 220);
const BLOCKED_COLOR: Color32 = Color32::from_rgb(210, 70, 70);
const ADDED_COLOR: Color32 = Color32::from_rgb(70, 170, 90);

enum Speaker {
    You,
    Assistant,
    Problem,
}

struct KeyService {
    provider: Provider,
    name: &'static str,
    keys_page: &'static str,
    hint: &'static str,
    note: &'static str,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Exchanges,
    Changes,
    Vault,
}

struct LogLine {
    direction: Direction,
    label: String,
    text: String,
}

pub struct App {
    tx: Sender<Command>,
    rx: Receiver<Event>,
    config: Config,
    key_input: String,
    models: Result<Vec<String>, String>,
    settings_note: String,
    project_info: String,
    chat: Vec<(Speaker, String)>,
    input: String,
    busy: bool,
    status: String,
    approval: Option<(String, String)>,
    log: Vec<LogLine>,
    changes: Vec<Change>,
    vault: Vec<(String, String)>,
    tab: Tab,
    chatgpt_email: Option<String>,
    chatgpt_models: Vec<String>,
    sign_in_cancel: Option<Arc<AtomicBool>>,
    show_welcome: bool,
    key_setup: Option<Provider>,
    remote_lines: Vec<RemoteLine>,
    secrets: Vec<String>,
    show_inspector: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut config = config::load();
        config.api_key = config::load_api_key(config.provider);
        let (event_tx, rx) = channel();
        let event_tx = Mutex::new(event_tx);
        let ctx = cc.egui_ctx.clone();
        let sink: Sink = Arc::new(move |event| {
            if let Ok(sender) = event_tx.lock() {
                let _ = sender.send(event);
            }
            ctx.request_repaint();
        });
        let tx = spawn_worker(config.clone(), config::data_dir(), sink);
        let models = fetch_models(&config.ollama_url);
        let saved = ChatGptAuth::load(&config::data_dir());
        let chatgpt_email = saved.is_connected().then(|| saved.email().to_string());
        App {
            chatgpt_email,
            chatgpt_models: Vec::new(),
            sign_in_cancel: None,
            show_welcome: false,
            key_setup: None,
            remote_lines: Vec::new(),
            secrets: Vec::new(),
            show_inspector: true,
            tx,
            rx,
            config,
            key_input: String::new(),
            models,
            settings_note: String::new(),
            project_info: String::new(),
            chat: Vec::new(),
            input: String::new(),
            busy: false,
            status: String::new(),
            approval: None,
            log: Vec::new(),
            changes: Vec::new(),
            vault: Vec::new(),
            tab: Tab::Exchanges,
        }
    }

    fn send(&self, command: Command) {
        let _ = self.tx.send(command);
    }

    fn pump_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Assistant(text) => self.chat.push((Speaker::Assistant, text)),
                Event::Error(text) => self.chat.push((Speaker::Problem, text)),
                Event::Status(text) => self.status = text,
                Event::Busy(busy) => {
                    self.busy = busy;
                    if !busy {
                        self.sign_in_cancel = None;
                    }
                }
                Event::ChatGpt {
                    email,
                    models,
                    selected,
                    welcome,
                } => {
                    let just_connected = self.sign_in_cancel.is_some() && email.is_some();
                    self.chatgpt_email = email;
                    self.chatgpt_models = models;
                    self.show_welcome |= welcome;
                    if just_connected {
                        self.config.provider = Provider::ChatGptPlan;
                        self.config.remote_url = config::CHATGPT_URL.into();
                        self.key_setup = None;
                    }
                    if let Some(model) = selected {
                        self.config.remote_model = model;
                    }
                    if just_connected {
                        self.persist();
                    }
                }
                Event::AskApproval { what, text } => self.approval = Some((what, text)),
                Event::Log {
                    direction,
                    label,
                    text,
                } => self.log.push(LogLine {
                    direction,
                    label,
                    text,
                }),
                Event::Changes(changes) => {
                    if !changes.is_empty() && changes.len() != self.changes.len() {
                        self.tab = Tab::Changes;
                        self.show_inspector = true;
                    }
                    self.changes = changes;
                }
                Event::Vault(entries) => self.vault = entries,
                Event::WorkspaceReady {
                    files,
                    names,
                    secrets,
                } => {
                    self.project_info = format!(
                        "{files} fichiers partageables, {names} noms et {} secrets détectés",
                        secrets.len()
                    );
                    self.secrets = secrets;
                }
                Event::Remote(line) => self.remote_lines.push(line),
            }
        }
    }

    fn pick_project(&mut self) {
        if let Some(folder) = rfd::FileDialog::new()
            .set_title("Dossier du projet")
            .pick_folder()
        {
            self.config.workspace = Some(folder.clone());
            self.persist();
            self.send(Command::OpenWorkspace(folder));
        }
    }

    fn persist(&mut self) {
        if let Err(error) = config::save(&self.config) {
            self.settings_note = format!("{error:#}");
        }
    }

    fn apply_settings(&mut self) {
        self.settings_note =
            "Réglages appliqués : nouvelle conversation avec l'IA en ligne.".into();
        let key = self.key_input.trim().to_string();
        if !key.is_empty() {
            match config::save_api_key(self.config.provider, &key) {
                Ok(()) => self.key_input.clear(),
                Err(error) => self.settings_note = format!("{error:#}"),
            }
            self.config.api_key = key;
        }
        self.persist();
        self.models = fetch_models(&self.config.ollama_url);
        self.send(Command::Configure(self.config.clone()));
    }

    fn submit(&mut self) {
        let text = self.input.trim().to_string();
        if !text.is_empty() && !self.busy {
            self.chat.push((Speaker::You, text.clone()));
            self.input.clear();
            self.busy = true; // sans attendre le worker, pour éviter un double envoi
            self.send(Command::Send(text));
        }
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("Anonimator");
                ui.separator();
                let can_switch = !self.busy && self.changes.is_empty();
                let button = ui.add_enabled(can_switch, egui::Button::new("Ouvrir un projet…"));
                let button = button.on_disabled_hover_text(
                    "Validez ou annulez d'abord les modifications en attente",
                );
                if button.clicked() {
                    self.pick_project();
                }
                match &self.config.workspace {
                    Some(path) => {
                        ui.label(RichText::new(path.display().to_string()).strong());
                        ui.label(RichText::new(&self.project_info).weak());
                    }
                    None => {
                        ui.label(RichText::new("aucun projet ouvert").weak());
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.toggle_value(&mut self.show_inspector, "Détails");
                });
            });
            ui.add_space(4.0);
        });
    }

    fn settings_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("settings").default_width(270.0).show(ctx, |ui| {
            ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(6.0);
                self.connection_section(ui);

                ui.add_space(14.0);
                ui.strong("IA locale");
                match &self.models {
                    Ok(_) => ui.colored_label(ADDED_COLOR, "Connectée"),
                    Err(message) => ui.colored_label(BLOCKED_COLOR, message.as_str()),
                };
                if let Ok(models) = &self.models {
                    let mut picked = None;
                    egui::ComboBox::from_id_salt("models")
                        .selected_text(self.config.local_model.as_str())
                        .width(ui.available_width())
                        .show_ui(ui, |ui| {
                            for model in models {
                                if ui.selectable_label(*model == self.config.local_model, model).clicked() {
                                    picked = Some(model.clone());
                                }
                            }
                        });
                    if let Some(model) = picked {
                        self.config.local_model = model;
                        self.persist();
                        self.send(Command::Configure(self.config.clone()));
                    }
                }

                ui.add_space(14.0);
                ui.strong("Confidentialité");
                let auto = ui.checkbox(&mut self.config.auto_anonymize, "Mode auto").on_hover_text(
                    "Cherche seul les noms du code, y compris les clés d'objets et les propriétés. L'IA en ligne peut moins bien reconnaître certaines bibliothèques.",
                );
                if auto.changed() {
                    self.persist();
                    self.send(Command::Configure(self.config.clone()));
                }
                ui.label(RichText::new("Secrets, commentaires et textes sont toujours masqués.").weak());
                ui.checkbox(&mut self.config.require_approval, "Valider chaque envoi");

                ui.add_space(10.0);
                egui::CollapsingHeader::new("Réglages avancés").show(ui, |ui| self.advanced_settings(ui));

                ui.add_space(10.0);
                if ui.add_enabled(!self.busy, egui::Button::new("Appliquer les réglages")).clicked() {
                    self.apply_settings();
                }
                if !self.settings_note.is_empty() {
                    ui.label(RichText::new(&self.settings_note).weak());
                }
            });
        });
    }

    fn connection_section(&mut self, ui: &mut egui::Ui) {
        ui.strong("IA en ligne");
        let full_width = egui::vec2(ui.available_width(), 30.0);

        if let Some(cancel) = self.sign_in_cancel.clone() {
            ui.label("Terminez la connexion dans votre navigateur…");
            if ui.button("Annuler").clicked() {
                cancel.store(true, Ordering::SeqCst);
            }
            return;
        }

        if self.config.provider == Provider::ChatGptPlan && self.chatgpt_email.is_some() {
            ui.colored_label(ADDED_COLOR, "ChatGPT connecté");
            ui.label(RichText::new(self.chatgpt_email.clone().unwrap_or_default()).weak());
            if !self.chatgpt_models.is_empty() {
                let mut picked = None;
                egui::ComboBox::from_id_salt("chatgpt_models")
                    .selected_text(self.config.remote_model.as_str())
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        for model in &self.chatgpt_models {
                            if ui
                                .selectable_label(*model == self.config.remote_model, model)
                                .clicked()
                            {
                                picked = Some(model.clone());
                            }
                        }
                    });
                if let Some(model) = picked {
                    self.config.remote_model = model;
                    self.persist();
                    self.send(Command::Configure(self.config.clone()));
                }
            }
            if ui
                .add_enabled(!self.busy, egui::Button::new("Se déconnecter"))
                .clicked()
            {
                self.send(Command::ChatGptSignOut);
            }
            ui.add_space(6.0);
        } else {
            let button = egui::Button::new("Continue with ChatGPT").min_size(full_width);
            if ui.add_enabled(!self.busy, button).clicked() {
                let cancel = Arc::new(AtomicBool::new(false));
                self.sign_in_cancel = Some(cancel.clone());
                self.busy = true;
                self.send(Command::ChatGptSignIn(cancel));
            }
            ui.label(RichText::new("Utilise votre forfait ChatGPT, sans clé d'API.").weak());
            ui.add_space(6.0);
        }

        self.key_service(
            ui,
            KeyService {
                provider: Provider::Gemini,
                name: "Gemini",
                keys_page: config::GEMINI_KEYS_PAGE,
                hint: "Clé Google AI Studio",
                note: "Niveau gratuit avec un compte Google. Hors d'Europe, Google peut utiliser et faire relire ce qui lui est envoyé en gratuit.",
            },
        );
        ui.add_space(6.0);
        self.key_service(
            ui,
            KeyService {
                provider: Provider::Anthropic,
                name: "Claude",
                keys_page: config::ANTHROPIC_KEYS_PAGE,
                hint: "sk-ant-…",
                note: "Claude exige une clé d'API : l'abonnement n'est pas utilisable ici.",
            },
        );
    }

    /// Bouton d'un service à clé : bascule si la clé existe, sinon ouvre la page pour en créer une.
    fn key_service(&mut self, ui: &mut egui::Ui, service: KeyService) {
        let connected = self.config.provider == service.provider && !self.config.api_key.is_empty();
        let editing = self.key_setup == Some(service.provider);
        if connected && !editing {
            ui.colored_label(
                ADDED_COLOR,
                format!("{} connecté par clé d'API", service.name),
            );
            ui.label(RichText::new(&self.config.remote_model).weak());
            if ui.button("Remplacer la clé").clicked() {
                self.key_setup = Some(service.provider);
                ui.ctx().open_url(egui::OpenUrl::new_tab(service.keys_page));
            }
            ui.label(RichText::new(service.note).weak());
            return;
        }
        let size = egui::vec2(ui.available_width(), 30.0);
        let button = egui::Button::new(format!("Se connecter à {}", service.name)).min_size(size);
        if ui.add_enabled(!self.busy, button).clicked() {
            if config::load_api_key(service.provider).is_empty() {
                self.key_setup = Some(service.provider);
                self.key_input.clear();
                ui.ctx().open_url(egui::OpenUrl::new_tab(service.keys_page));
            } else {
                self.use_key(service.provider);
            }
        }
        if self.key_setup != Some(service.provider) {
            ui.label(RichText::new(service.note).weak());
            return;
        }
        ui.label("Créez une clé dans la page ouverte, puis collez-la ici :");
        ui.add(
            TextEdit::singleline(&mut self.key_input)
                .password(true)
                .hint_text(service.hint)
                .desired_width(f32::INFINITY),
        );
        let filled = !self.key_input.trim().is_empty();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    filled && !self.busy,
                    egui::Button::new("Enregistrer la clé"),
                )
                .clicked()
            {
                self.use_key(service.provider);
            }
            if ui.button("Annuler").clicked() {
                self.key_setup = None;
                self.key_input.clear();
            }
        });
    }

    fn use_key(&mut self, provider: Provider) {
        let (url, model) = match provider {
            Provider::Gemini => (config::GEMINI_URL, config::GEMINI_MODEL),
            _ => (config::ANTHROPIC_URL, config::ANTHROPIC_MODEL),
        };
        self.config.provider = provider;
        self.config.remote_url = url.into();
        self.config.remote_model = model.into();
        self.config.api_key = config::load_api_key(provider);
        self.key_setup = None;
        self.apply_settings();
    }

    fn advanced_settings(&mut self, ui: &mut egui::Ui) {
        ui.label("Termes supplémentaires à masquer, un par ligne (facultatif)");
        ui.add(
            TextEdit::multiline(&mut self.config.custom_terms)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
        ui.add_space(8.0);
        ui.label("Adresse d'Ollama");
        ui.add(TextEdit::singleline(&mut self.config.ollama_url).desired_width(f32::INFINITY));
        ui.label("Modèle local");
        ui.add(TextEdit::singleline(&mut self.config.local_model).desired_width(f32::INFINITY));
        ui.add_space(8.0);
        ui.label("Fournisseur en ligne");
        let before = self.config.provider;
        ui.radio_value(
            &mut self.config.provider,
            Provider::ChatGptPlan,
            "Forfait ChatGPT",
        );
        ui.radio_value(
            &mut self.config.provider,
            Provider::Anthropic,
            "Claude (clé d'API)",
        );
        ui.radio_value(
            &mut self.config.provider,
            Provider::Gemini,
            "Gemini (clé d'API)",
        );
        ui.radio_value(
            &mut self.config.provider,
            Provider::OpenAiCompatible,
            "Compatible OpenAI (clé d'API)",
        );
        if before != self.config.provider {
            let (url, model) = match self.config.provider {
                Provider::Anthropic => (config::ANTHROPIC_URL, config::ANTHROPIC_MODEL),
                Provider::Gemini => (config::GEMINI_URL, config::GEMINI_MODEL),
                Provider::OpenAiCompatible => (config::OPENAI_URL, ""),
                Provider::ChatGptPlan => (config::CHATGPT_URL, ""),
            };
            self.config.remote_url = url.into();
            self.config.remote_model = model.into();
            self.config.api_key = config::load_api_key(self.config.provider);
        }
        ui.label("Adresse");
        ui.add(TextEdit::singleline(&mut self.config.remote_url).desired_width(f32::INFINITY));
        ui.label("Modèle");
        ui.add(TextEdit::singleline(&mut self.config.remote_model).desired_width(f32::INFINITY));
        if self.config.provider != Provider::ChatGptPlan {
            ui.label(if self.config.api_key.is_empty() {
                "Clé d'API (manquante)"
            } else {
                "Clé d'API (enregistrée)"
            });
            ui.add(
                TextEdit::singleline(&mut self.key_input)
                    .password(true)
                    .hint_text("Coller pour remplacer")
                    .desired_width(f32::INFINITY),
            );
        }
        ui.add_space(8.0);
        ui.checkbox(&mut self.config.allow_prose, "Partager Markdown, HTML et texte")
            .on_hover_text("Leur contenu ne passe que par les listes de termes : le texte métier peut rester lisible.");
    }

    fn welcome_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_welcome {
            return;
        }
        egui::Modal::new(egui::Id::new("chatgpt_welcome")).show(ctx, |ui| {
            ui.set_max_width(440.0);
            ui.heading("You're using your ChatGPT plan");
            ui.add_space(6.0);
            ui.label("Les requêtes envoyées à l'IA en ligne sont décomptées de votre forfait ChatGPT. Vous pouvez suivre et limiter cet usage dans les réglages de ChatGPT.");
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Got it").clicked() {
                    self.show_welcome = false;
                }
                ui.hyperlink_to("Manage usage", chatgpt::USAGE_URL);
            });
        });
    }

    fn inspector_panel(&mut self, ctx: &egui::Context) {
        if !self.show_inspector {
            return;
        }
        egui::SidePanel::right("inspector")
            .default_width(340.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::Exchanges,
                        format!("Échanges ({})", self.log.len()),
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::Changes,
                        format!("Modifications ({})", self.changes.len()),
                    );
                    ui.selectable_value(
                        &mut self.tab,
                        Tab::Vault,
                        format!("Coffre ({})", self.vault.len()),
                    );
                });
                ui.separator();
                match self.tab {
                    Tab::Exchanges => self.exchanges_tab(ui),
                    Tab::Changes => self.changes_tab(ui),
                    Tab::Vault => self.vault_tab(ui),
                }
            });
    }

    fn exchanges_tab(&self, ui: &mut egui::Ui) {
        if self.log.is_empty() {
            ui.label(
                RichText::new(
                    "Tout ce qui part vers l'IA en ligne et en revient s'affichera ici, tel quel.",
                )
                .weak(),
            );
            return;
        }
        ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                for (index, line) in self.log.iter().enumerate() {
                    let (arrow, color) = match line.direction {
                        Direction::Out => ("Envoyé", OUT_COLOR),
                        Direction::In => ("Reçu", IN_COLOR),
                        Direction::Blocked => ("Bloqué", BLOCKED_COLOR),
                    };
                    let title = RichText::new(format!("{arrow} · {}", line.label)).color(color);
                    egui::CollapsingHeader::new(title)
                        .id_salt(index)
                        .default_open(line.text.len() < 400)
                        .show(ui, |ui| {
                            ui.add(egui::Label::new(RichText::new(&line.text).monospace()).wrap());
                        });
                }
            });
    }

    fn changes_tab(&mut self, ui: &mut egui::Ui) {
        if self.changes.is_empty() {
            ui.label(RichText::new("Les fichiers proposés par l'IA attendront ici votre validation : rien n'est écrit avant.").weak());
            return;
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.busy, egui::Button::new("Écrire sur le disque"))
                .clicked()
            {
                self.send(Command::ApplyChanges);
            }
            if ui
                .add_enabled(!self.busy, egui::Button::new("Tout annuler"))
                .clicked()
            {
                self.send(Command::DiscardChanges);
            }
        });
        ui.separator();
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            for change in &self.changes {
                egui::CollapsingHeader::new(RichText::new(&change.path).strong())
                    .default_open(true)
                    .show(ui, |ui| show_diff(ui, change));
            }
        });
    }

    fn vault_tab(&self, ui: &mut egui::Ui) {
        if !self.secrets.is_empty() {
            egui::CollapsingHeader::new(format!("Secrets détectés ({})", self.secrets.len())).show(
                ui,
                |ui| {
                    ScrollArea::vertical()
                        .id_salt("secrets")
                        .max_height(180.0)
                        .show(ui, |ui| {
                            for secret in &self.secrets {
                                ui.add(egui::Label::new(RichText::new(secret).monospace()).wrap());
                            }
                        });
                },
            );
            ui.separator();
        }
        ui.label(RichText::new("Correspondances conservées sur cette machine uniquement.").weak());
        ui.separator();
        ScrollArea::vertical().auto_shrink(false).show_rows(
            ui,
            18.0,
            self.vault.len(),
            |ui, range| {
                for (token, value) in &self.vault[range] {
                    let shown: String = value
                        .chars()
                        .take(70)
                        .collect::<String>()
                        .replace(['\n', '\r'], " ");
                    ui.horizontal(|ui| {
                        ui.monospace(RichText::new(token).color(OUT_COLOR));
                        ui.add(egui::Label::new(shown).truncate());
                    });
                }
            },
        );
    }

    fn input_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("input").show(ctx, |ui| {
            ui.add_space(6.0);
            if self.config.provider == Provider::ChatGptPlan && self.chatgpt_email.is_some() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Using ChatGPT plan").weak());
                    ui.hyperlink_to("Manage usage", chatgpt::USAGE_URL);
                });
            }
            if !self.status.is_empty() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(&self.status);
                });
            }
            ui.horizontal(|ui| {
                let send_width = 90.0;
                let edit = TextEdit::multiline(&mut self.input)
                    .hint_text("Décrivez ce que vous voulez. Entrée pour envoyer, Maj+Entrée pour aller à la ligne.")
                    .desired_rows(2)
                    .desired_width(ui.available_width() - send_width)
                    .return_key(Some(KeyboardShortcut::new(Modifiers::SHIFT, Key::Enter)));
                let response = ui.add(edit);
                let enter = response.has_focus() && ui.input(|i| i.key_pressed(Key::Enter) && !i.modifiers.shift);
                let clicked = ui.add_enabled(!self.busy, egui::Button::new("Envoyer")).clicked();
                if enter || clicked {
                    self.submit();
                    response.request_focus();
                }
            });
            ui.add_space(6.0);
        });
    }

    fn chat_panel(&mut self, ctx: &egui::Context) {
        let mut open_clicked = false;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |columns| {
                columns[0].strong("IA locale");
                columns[0].separator();
                if self.chat.is_empty() {
                    columns[0].vertical_centered(|ui| {
                        ui.add_space(ui.available_height() * 0.3);
                        ui.heading("Vos noms et vos textes restent chez vous.");
                        ui.add_space(6.0);
                        ui.label("Vous parlez à l'IA locale. L'IA en ligne reçoit votre code avec des pseudonymes.");
                        if self.config.workspace.is_none() {
                            ui.add_space(12.0);
                            open_clicked = ui.button("Ouvrir un projet…").clicked();
                        }
                    });
                } else {
                    ScrollArea::vertical()
                        .id_salt("local_chat")
                        .stick_to_bottom(true)
                        .auto_shrink(false)
                        .show(&mut columns[0], |ui| {
                            for (speaker, text) in &self.chat {
                                let (name, color) = match speaker {
                                    Speaker::You => ("Vous", ui.visuals().strong_text_color()),
                                    Speaker::Assistant => ("IA locale", ADDED_COLOR),
                                    Speaker::Problem => ("Problème", BLOCKED_COLOR),
                                };
                                ui.add_space(8.0);
                                ui.label(RichText::new(name).color(color).strong());
                                ui.add(egui::Label::new(text).selectable(true).wrap());
                            }
                        });
                }

                columns[1].strong("IA en ligne");
                columns[1].separator();
                if self.remote_lines.is_empty() {
                    columns[1].label(
                        RichText::new("Ses réponses et ses actions s'afficheront ici, avec vos vrais noms. Elle ne voit que les pseudonymes.").weak(),
                    );
                } else {
                    ScrollArea::vertical()
                        .id_salt("remote_chat")
                        .stick_to_bottom(true)
                        .auto_shrink(false)
                        .show(&mut columns[1], |ui| {
                            for line in &self.remote_lines {
                                match line {
                                    RemoteLine::Activity(text) => {
                                        ui.add(egui::Label::new(RichText::new(text).weak().small()).wrap());
                                    }
                                    RemoteLine::Text(text) => {
                                        ui.add_space(8.0);
                                        ui.add(egui::Label::new(text).selectable(true).wrap());
                                        ui.add_space(8.0);
                                    }
                                }
                            }
                        });
                }
            });
        });
        if open_clicked {
            self.pick_project();
        }
    }

    fn approval_dialog(&mut self, ctx: &egui::Context) {
        let Some((what, text)) = &self.approval else {
            return;
        };
        let mut answer = None;
        egui::Modal::new(egui::Id::new("approval")).show(ctx, |ui| {
            ui.set_width((ctx.screen_rect().width() * 0.7).min(860.0));
            ui.heading(what);
            ui.label("Voici exactement ce qui va quitter votre machine :");
            ui.add_space(4.0);
            ScrollArea::vertical()
                .max_height(ctx.screen_rect().height() * 0.6)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(text.as_str()).monospace()).wrap());
                });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Envoyer").clicked() {
                    answer = Some(Approval::Once);
                }
                if ui.button("Tout envoyer pour cette tâche").clicked() {
                    answer = Some(Approval::ForThisTask);
                }
                if ui.button("Refuser").clicked() {
                    answer = Some(Approval::Refuse);
                }
            });
        });
        if let Some(answer) = answer {
            self.approval = None;
            self.send(Command::Answer(answer));
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump_events();
        self.top_bar(ctx);
        self.settings_panel(ctx);
        self.inspector_panel(ctx);
        self.input_bar(ctx);
        self.chat_panel(ctx);
        self.approval_dialog(ctx);
        self.welcome_dialog(ctx);
    }
}

fn fetch_models(url: &str) -> Result<Vec<String>, String> {
    LocalAi::models(url).map_err(|_| "Ollama non détecté : lancez « ollama serve »".to_string())
}

fn show_diff(ui: &mut egui::Ui, change: &Change) {
    let diff = TextDiff::from_lines(&change.before, &change.after);
    for group in diff.grouped_ops(2) {
        for op in group {
            for line in diff.iter_changes(&op) {
                let (sign, color) = match line.tag() {
                    ChangeTag::Delete => ("-", BLOCKED_COLOR),
                    ChangeTag::Insert => ("+", ADDED_COLOR),
                    ChangeTag::Equal => (" ", ui.visuals().weak_text_color()),
                };
                let text = format!("{sign} {}", line.value().trim_end_matches(['\r', '\n']));
                ui.add(egui::Label::new(RichText::new(text).monospace().color(color)).wrap());
            }
        }
        ui.separator();
    }
}
