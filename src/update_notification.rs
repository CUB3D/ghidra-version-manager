use crate::cache::Cacher;
use clap::Parser;
use iced::{Color, Task, Theme};
use notify_rust::Notification;
use std::sync::{Arc, RwLock};

pub async fn show_update_notification(
    cacher: &mut Cacher,
    previous_latest_version: String,
) -> UpdateDialogAction {
    // Use the icon from the last launched version
    let icon_path = cacher
        .last_launched()
        .map(|c| {
            c.path
                .join("support")
                .join("ghidra_ico.png")
                .to_string_lossy()
                .to_string()
        })
        .unwrap_or("ghidra".to_string());

    let _ = Notification::new()
        .summary(&format!(
            "New ghidra version available: {}",
            cacher.cache.latest_known
        ))
        .icon(&icon_path)
        .show();

    // If a prompt is enabled, show the GUI to update
    // If not, just launch it as if nothing happened
    if cacher.cache.prefs.prompt_for_update {
        spawn_update_prompt_dialog(cacher, previous_latest_version).await
    } else {
        UpdateDialogAction::Launch(None)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UpdateDialogActionInternal {
    /// Quit the GUI, don't start Ghidra
    Quit,

    /// Quit the GUI, but do start Ghidra
    Launch,

    /// Download new Ghidra version, Quit the GUI
    Update,
}

#[derive(Clone, Debug)]
pub enum UpdateDialogAction {
    /// Quit, don't start Ghidra
    Quit,

    /// Launch ghidra, optionally override the target version
    Launch(Option<String>),
}

#[derive(Clone)]
struct UpdateDialog {
    current_version: String,
    latest_version: String,

    next_action: Arc<RwLock<UpdateDialogActionInternal>>,
}

#[derive(Debug, Clone, Copy)]
pub enum Message {
    /// Download new Ghidra version, Quit the GUI
    Update,

    /// Quit the GUI, but do start Ghidra
    Launch,

    /// Quit the GUI, don't start Ghidra
    Quit,
}

use crate::args::arguments::Args;
use iced::widget::{Column, button, column, row, text};

impl UpdateDialog {
    pub fn view(&self) -> Column<'_, Message> {
        column![
            text("A new version of Ghidra is available"),
            row![
                text("You have: "),
                text(&self.current_version).color(Color::from_rgb(1., 0., 0.)),
            ],
            row![
                text("New version: "),
                text(&self.latest_version).color(Color::from_rgb(0., 1., 0.)),
            ],
            row![
                button("Update and launch").on_press(Message::Update),
                button("Launch old").on_press(Message::Launch),
                button("Quit").on_press(Message::Quit),
            ]
            .spacing(15.),
        ]
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Update => {
                *self.next_action.write().unwrap() = UpdateDialogActionInternal::Update;
                iced::exit()
            }
            Message::Launch => {
                *self.next_action.write().unwrap() = UpdateDialogActionInternal::Launch;
                iced::exit()
            }
            Message::Quit => {
                *self.next_action.write().unwrap() = UpdateDialogActionInternal::Quit;
                iced::exit()
            }
        }
    }
}

pub async fn spawn_update_prompt_dialog(
    cacher: &mut Cacher,
    previous_latest_version: String,
) -> UpdateDialogAction {
    let next_action = Arc::new(RwLock::new(UpdateDialogActionInternal::Quit));

    let dialog = UpdateDialog {
        current_version: previous_latest_version,
        latest_version: cacher.cache.latest_known.clone(),
        next_action: Arc::clone(&next_action),
    };

    let _ = iced::application(
        move || dialog.clone(),
        UpdateDialog::update,
        UpdateDialog::view,
    )
    .theme(Theme::Dark)
    .centered()
    .window_size((350., 125.))
    .run();

    let next_action = *next_action.read().unwrap();

    if let UpdateDialogActionInternal::Update = next_action {
        crate::update_with_prefs_backup(
            cacher,
            &Args::parse(),
            &crate::get_gvm_config_dir().unwrap(),
            &cacher.cache.latest_known.clone(),
        )
        .await
        .unwrap();
    }

    match next_action {
        UpdateDialogActionInternal::Launch => UpdateDialogAction::Launch(None),
        UpdateDialogActionInternal::Quit => UpdateDialogAction::Quit,
        UpdateDialogActionInternal::Update => {
            UpdateDialogAction::Launch(Some(cacher.cache.latest_known.clone()))
        }
    }
}
