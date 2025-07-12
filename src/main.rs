mod extensions;

use crate::cache::Cacher;
use crate::extensions::ExtSubcommand;
use anyhow::Context;
use chrono::Utc;
use clap::{Parser, Subcommand};
use std::process::Command;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

pub mod cache;
pub mod install;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Cmd,

    /// Enable expanded logging
    #[arg(short, long, default_value = "false")]
    pub verbose: bool,

    /// Disable network access
    #[arg(short, long, default_value = "false")]
    pub offline: bool,
}

#[derive(Debug, Subcommand)]
pub enum DefaultSubCmd {
    /// Display the current Ghidra version
    Show,

    /// Set the default version, installing it if needed
    Set { tag: String },
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    #[command(alias = "ls")]
    /// List the available Ghidra versions
    List,

    #[command(alias = "i")]
    /// Install a Ghidra version
    Install { tag: String },

    #[command(alias = "r")]
    /// Launch Ghidra, unless specified launches the default version
    Run { tag: Option<String> },

    #[command(alias = "del")]
    /// Remove a Ghidra version
    Uninstall { tag: String },

    /// Manage the default version
    Default {
        #[clap(subcommand)]
        cmd: DefaultSubCmd,
    },

    #[command(alias = "u")]
    /// Update the default version
    Update,

    #[command(alias = "e")]
    /// Manage extensions
    Extensions {
        #[clap(subcommand)]
        cmd: ExtSubcommand,
    },
}

pub async fn update_latest_version(cacher: &mut Cacher) -> anyhow::Result<()> {
    let octocrab = octocrab::instance();

    let v = octocrab
        .repos("NationalSecurityAgency", "ghidra")
        .releases()
        .get_latest()
        .await?;

    if cacher.cache.latest_known != v.tag_name {
        info!("🚀 New latest version available: {}", v.tag_name);
    }

    cacher.with_cache(|c| {
        c.latest_known = v.tag_name;
    })?;

    Ok(())
}

// TODO:
// ext updates

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
    let path = home.join(".local/opt/gvm/");
    let _ = std::fs::create_dir_all(&path);

    let cache_path = path.join("cache.toml");
    let mut cacher = Cacher::load(cache_path)?;

    if Utc::now()
        .signed_duration_since(cacher.cache.last_update_check)
        .num_hours()
        > 18
        || cacher.cache.latest_known.is_empty()
    {
        debug!("Checking for updates");
        update_latest_version(&mut cacher).await?;
        cacher.with_cache(|c| c.last_update_check = Utc::now())?;
    }

    match &args.cmd {
        Cmd::Extensions { cmd } => {
            extensions::handle_ext_cmd(&mut cacher, &path, &args, cmd).await?;
        }
        Cmd::Update => {
            if cacher.cache.default != "latest" {
                error!("Can't update when default is a fixed version");
                return Ok(());
            }

            let latest = cacher.cache.latest_known.clone();
            if !cacher.is_installed(&latest) {
                info!("✨✨✨ New version available: {latest} ✨✨✨");
                install::install_version(&mut cacher, &args, &path, &latest).await?;
            } else {
                info!("You have the latest version already!");
            }
        }
        Cmd::Default { cmd } => match cmd {
            DefaultSubCmd::Show => {
                info!("{}", cacher.cache.default);
            }
            DefaultSubCmd::Set { tag } => {
                cacher.with_cache(|c| {
                    c.default = tag.clone();
                })?;

                if !cacher.is_installed(tag) {
                    install::install_version(&mut cacher, &args, &path, tag).await?;
                }
            }
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
                Some(tag) => tag.clone(),
                None => cacher.default_explicit(),
            };

            if !cacher.is_installed(&tag) {
                install::install_version(&mut cacher, &args, &path, &tag).await?;
            }

            let path = &cacher.cache.entries.get(&tag).as_ref().unwrap().path;
            let runner = path.join("ghidraRun");
            if !runner.exists() {
                cacher.with_cache(|c| {
                    c.entries.remove(&tag);
                })?;
                error!("Failed to find runner, did the installation get removed?");
                return Ok(());
            }
            info!("Launching {}", runner.display());
            Command::new(&runner).spawn()?;
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
