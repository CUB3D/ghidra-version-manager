mod extensions;

use crate::args::arguments::Args;
use crate::args::cmd::Cmd;
use crate::args::default_subcommand::DefaultSubCmd;
use crate::args::prefs_subcommand::PrefsSubCmd;
use crate::args::settings_subcommand::SettingsSubcommand;
use crate::cache::Cacher;
use crate::prefs_backup::backup_generator::BackupGenerator;
use crate::prefs_backup::backup_restorer::BackupRestorer;
use anyhow::Context;
use chrono::Utc;
use clap::Parser;
use notify_rust::Notification;
use std::os::unix::process::CommandExt;
use std::process::Command;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

pub mod args;
pub mod cache;
mod exit_codes;
pub mod ghidra_props_parser;
pub mod install;
mod prefs_backup;

/// Check if there is an update available
///
/// Returns Ok(true) if there is an update, Ok(false) if not
/// Updates the cache with the new version if one is fone otherwise it is unchanged
///
/// # Errors
/// Returns error if the update check
pub async fn update_latest_version(cacher: &mut Cacher) -> anyhow::Result<bool> {
    let octocrab = octocrab::instance();

    let v = octocrab
        .repos("NationalSecurityAgency", "ghidra")
        .releases()
        .get_latest()
        .await?;

    if cacher.cache.latest_known != v.tag_name {
        info!("🔔🔔🔔 New version available: {} 🔔🔔🔔", v.tag_name);

        cacher.with_cache(|c| {
            c.latest_known = v.tag_name;
        })?;

        return Ok(true);
    }

    Ok(false)
}

async fn do_update_check(cacher: &mut Cacher, args: &Args) -> anyhow::Result<bool> {
    debug!("Checking for updates");

    let new_version = match update_latest_version(cacher).await {
        Ok(v) => v,
        Err(e) => {
            warn!("Failed to check for update: {e:?}");
            return Ok(false);
        }
    };

    // Show update notification if running in launcher mode
    if new_version && args.launcher {
        let _ = Notification::new()
            .summary("New ghidra version available")
            .icon("ghidra")
            .show();
    }
    cacher.with_cache(|c| c.last_update_check = Utc::now())?;

    Ok(new_version)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let home = std::env::home_dir().context("Couldn't determine home directory")?;
    let path = if cfg!(target_family = "unix") {
        home.join(".local/opt/gvm/")
    } else {
        home.join("AppData").join("Local").join("gvm")
    };

    let _ = std::fs::create_dir_all(&path);

    let cache_path = path.join("cache.toml");
    let mut cacher = Cacher::load(cache_path)?;

    if args.cmd.allow_update_check()
        && Utc::now()
            .signed_duration_since(cacher.cache.last_update_check)
            .num_hours()
            > 18
        || cacher.cache.latest_known.is_empty()
    {
        do_update_check(&mut cacher, &args).await?;
    }

    match &args.cmd {
        Cmd::Locate { tag } => {
            let tag = match tag {
                Some(tag) => match tag.as_str() {
                    "default" => cacher.default_explicit(),
                    "latest" => cacher.cache.latest_known.clone(),
                    _ => tag.to_string(),
                },
                None => cacher.default_explicit(),
            };

            if let Some(cache_entry) = cacher.cache.entries.get(&tag) {
                println!("{}", cache_entry.path.display());
            } else {
                eprintln!("Not found");
                std::process::exit(exit_codes::EXIT_CODE_NOT_FOUND);
            }
        }
        Cmd::Settings { cmd } => match cmd {
            SettingsSubcommand::Restore { src, tag } => {
                if !cfg!(unix) {
                    error!("This command is only supported on unix");
                    return Ok(());
                }

                let tag = match tag {
                    Some(tag) => match tag.as_str() {
                        "default" => cacher.default_explicit(),
                        "latest" => cacher.cache.latest_known.clone(),
                        _ => tag.to_string(),
                    },
                    None => cacher.default_explicit(),
                };

                if let Some(cache_entry) = cacher.cache.entries.get(&tag) {
                    BackupRestorer::from_path(src)?.restore_to_cached_version(cache_entry)?;
                } else {
                    error!("That version isn't installed");
                }
            }
            SettingsSubcommand::Backup { tag, out } => {
                if !cfg!(unix) {
                    error!("This command is only supported on unix");
                    return Ok(());
                }

                let tag = match tag {
                    Some(tag) => match tag.as_str() {
                        "default" => cacher.default_explicit(),
                        "latest" => cacher.cache.latest_known.clone(),
                        _ => tag.to_string(),
                    },
                    None => cacher.default_explicit(),
                };

                if let Some(cache_entry) = cacher.cache.entries.get(&tag) {
                    let backup = BackupGenerator::from_cached_version(cache_entry, &tag)?;
                    std::fs::write(out, backup.backup_data).context("Failed to save backup")?;
                } else {
                    error!("That version isn't installed");
                }
            }
        },
        Cmd::CheckUpdate => {
            // Note: Not saving here so we don't lose the old value here if the check fails
            cacher.cache.latest_known = String::new();
            if !do_update_check(&mut cacher, &args).await? {
                info!("You have the latest version, I've checked");
            }
        }
        Cmd::Extensions { cmd } => {
            extensions::handle_ext_cmd(&mut cacher, &path, &args, cmd).await?;
        }
        Cmd::Update => {
            if cacher.cache.default != "latest" {
                error!("Can't update when default is a fixed version");
                return Ok(());
            }

            let latest = cacher.cache.latest_known.clone();
            if cacher.is_installed(&latest) {
                info!("You have the latest version already!");
            } else {
                // Backup prefs for current version
                let last_launched = cacher.cache.last_launched.clone();
                let restorer = if cfg!(unix)
                    && let Some(original_version) = cacher.cache.entries.get(&last_launched)
                {
                    info!("Backing up config from last launched version {last_launched}");
                    Some(
                        BackupGenerator::from_cached_version(original_version, &last_launched)?
                            .restorer(),
                    )
                } else {
                    None
                };

                install::install_version(&mut cacher, &args, &path, &latest).await?;

                if cfg!(unix)
                    && let Some(restorer) = restorer
                    && let Some(new_version) = cacher.cache.entries.get(&latest)
                {
                    info!("Restoring config to {latest}");
                    restorer.restore_to_cached_version(new_version)?;
                }
            }
        }
        Cmd::Default { cmd } => match cmd {
            DefaultSubCmd::Show => {
                info!("{}", cacher.cache.default);
            }
            DefaultSubCmd::Set { tag } => {
                cacher.with_cache(|c| {
                    c.default.clone_from(tag);
                })?;

                if !cacher.is_installed(tag) {
                    install::install_version(&mut cacher, &args, &path, tag).await?;
                }
            }
        },
        Cmd::Prefs { cmd } => match cmd {
            PrefsSubCmd::Show => {
                let yn = if cacher.cache.prefs.pyghidra {
                    "yes"
                } else {
                    "no"
                };
                info!("Use PyGhidra in launchers? {{py3}} [{yn}]");
                info!(
                    "Override ui scale {{scale}} [{}]",
                    cacher.cache.prefs.ui_scale_override
                );
            }
            PrefsSubCmd::Set { key, value } => match key.as_str() {
                "py3" => {
                    cacher.with_cache(|c: &mut cache::Cache| {
                        c.prefs.pyghidra = *value == "true";
                    })?;
                }
                "scale" => {
                    cacher.with_cache(|c: &mut cache::Cache| {
                        c.prefs.ui_scale_override =
                            value.parse::<u32>().expect("Failed to parse as number");
                    })?;
                }
                _ => error!("Unknown key"),
            },
        },
        Cmd::Uninstall { tag } => {
            let tag = match tag.as_str() {
                "default" => cacher.default_explicit(),
                "latest" => cacher.cache.latest_known.clone(),
                _ => tag.to_string(),
            };

            if let Some(cache_entry) = cacher.cache.entries.get(&tag) {
                std::fs::remove_dir_all(&cache_entry.path).context("Failed to delete directory")?;
                if let Some(launcher) = &cache_entry.launcher {
                    if std::fs::metadata(launcher)?.is_dir() {
                        std::fs::remove_dir_all(launcher).context("Failed to delete launcher")?;
                    } else {
                        std::fs::remove_file(launcher).context("Failed to delete launcher")?;
                    }
                }

                cacher.with_cache(|c| {
                    c.entries.remove(&tag);
                })?;
            } else {
                error!("That version isn't installed");
            }
        }
        Cmd::Run { tag } => {
            let tag = match tag {
                Some(tag) => match tag.as_str() {
                    "default" => cacher.default_explicit(),
                    "latest" => cacher.cache.latest_known.clone(),
                    _ => tag.to_string(),
                },
                None => cacher.default_explicit(),
            };

            if !cacher.is_installed(&tag) {
                // Backup prefs for current version
                let last_launched = cacher.cache.last_launched.clone();
                let restorer = if cfg!(unix)
                    && let Some(original_version) = cacher.cache.entries.get(&last_launched)
                {
                    info!("Backing up config from last launched version {last_launched}");
                    Some(
                        BackupGenerator::from_cached_version(original_version, &last_launched)?
                            .restorer(),
                    )
                } else {
                    None
                };

                install::install_version(&mut cacher, &args, &path, &tag).await?;

                if cfg!(unix)
                    && let Some(restorer) = restorer
                    && let Some(new_version) = cacher.cache.entries.get(&tag)
                {
                    info!("Restoring config to {tag}");
                    restorer.restore_to_cached_version(new_version)?;
                }
            }
            cacher.with_cache(|c| {
                c.last_launched = tag.clone();
            })?;

            let path = &cacher.cache.entries.get(&tag).as_ref().unwrap().path;
            let runner = if cacher.cache.prefs.pyghidra {
                if cfg!(target_family = "unix") {
                    path.join("support/pyghidraRun")
                } else {
                    path.join("support/pyghidraRun.bat")
                }
            } else if cfg!(target_family = "unix") {
                path.join("ghidraRun")
            } else {
                path.join("ghidraRun.bat")
            };

            if !runner.exists() {
                cacher.with_cache(|c| {
                    c.entries.remove(&tag);
                })?;
                error!("Failed to find runner, did the installation get removed?");
                return Ok(());
            }
            info!("Launching {}", runner.display());
            if cfg!(target_os = "linux") {
                return Err(anyhow::anyhow!(Command::new(&runner).exec()));
            } else {
                Command::new(&runner).spawn()?;
            }
        }
        Cmd::Install { tag } => {
            install::install_version(&mut cacher, &args, &path, tag).await?;
        }
        Cmd::List => {
            let octocrab = octocrab::instance();

            // Returns the first page of all issues.
            let page = octocrab
                .repos("NationalSecurityAgency", "ghidra")
                .releases()
                .list()
                .per_page(100)
                .send()
                .await?;

            let results = octocrab.all_pages(page).await?;

            info!("Available releases:");
            for c in &results {
                if args.verbose {
                    // println!("{:#?}", c);
                    if let Some(name) = &c.name {
                        info!("name: {name}");
                    }
                    if let Some(created_at) = c.created_at {
                        info!("date: {created_at}");
                    }

                    let asset = c.assets.first();
                    if let Some(asset) = asset {
                        info!("URL: {}", asset.url);
                    }
                    info!("--------");
                } else {
                    let mut out = format!("- {}", c.tag_name);
                    if cacher.is_installed(&c.tag_name) {
                        out.push_str(" [installed]");
                    }
                    if cacher.default_explicit() == c.tag_name {
                        out.push_str(" [default]");
                    }
                    info!("{}", out);
                }
            }
        }
    }

    Ok(())
}
