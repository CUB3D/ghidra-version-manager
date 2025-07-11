use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use reqwest::Client;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Cmd,

    /// Enable expanded logging
    #[clap(short, long, default_value = "false")]
    pub verbose: bool,

    /// Disable network access
    #[clap(short, long, default_value = "false")]
    pub offline: bool,
}

#[derive(Debug, Subcommand)]
pub enum DefaultSubCmd {
    /// Display the current Ghidra version
    Show,

    /// Set the default version, installing it if needed
    Set {
        tag: String,
    }
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// List the available Ghidra versions
    List,

    /// Install a Ghidra version
    Install {
        tag: String,
    },

    /// Launch Ghidra, unless specified launches the default version
    Run {
        tag: Option<String>,
    },

    /// Remove a Ghidra version
    Uninstall {
        tag: String,
    },

    /// Manage the default version
    Default {
        #[clap(subcommand)]
        cmd: DefaultSubCmd,
    },

    /// Update the default version
    Update,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct CacheEntry {
    pub path: PathBuf,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Cache {
    pub entries: HashMap<String, CacheEntry>,
    pub default: String,
    pub latest_known: String,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            entries: Default::default(),
            default: "latest".to_string(),
            latest_known: "Ghidra_11.3_build".to_string(),
        }
    }
}

pub struct Cacher {
    pub cache: Cache,
    pub cache_path: PathBuf
}

impl Cacher {
    pub fn load(cache_path: PathBuf) -> anyhow::Result<Self> {
        let cache_data = std::fs::read_to_string(&cache_path).context("Failed to read cache data").and_then(|s| {
            toml::from_str(&s).context("Failed to parse cache data")
        }).unwrap_or_default();

        Ok(Self { cache: cache_data, cache_path })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let s = toml::to_string(&self.cache)?;
        std::fs::write(&self.cache_path, &s).context("Failed to write cache data")?;
        Ok(())
    }

    pub fn default_explicit(&self) -> String {
        let v = match self.cache.default.as_str() {
            "latest" => {
                self.cache.latest_known.clone()
            },
            _ => self.cache.default.clone()
        };
        v
    }
}

pub async fn update_latest_version(cacher: &mut Cacher) -> anyhow::Result<()> {
    let octocrab = octocrab::instance();

    let v =octocrab.repos("NationalSecurityAgency", "ghidra")
        .releases()
        .get_latest()
        .await?;

    if cacher.cache.latest_known != v.tag_name {
        info!("🚀 New latest version available: {}", v.tag_name);
    }

    cacher.cache.latest_known = v.tag_name;
    cacher.save()?;

    Ok(())
}

pub async fn install_version(cacher: &mut Cacher, args: &Args, path: &PathBuf, tag: &String) -> anyhow::Result<()> {
    if cacher.cache.entries.get(tag).is_some() {
        info!("That version is already installed");
        return Ok(());
    }

    let tag = match tag.as_str() {
        "default" => cacher.default_explicit(),
        "latest" => cacher.cache.latest_known.clone(),
        _ => tag.to_string(),
    };

    let octocrab = octocrab::instance();

    let rel = octocrab.repos("NationalSecurityAgency", "ghidra")
        .releases()
        .get_by_tag(&tag)
        .await?;

    let asset = rel.assets.first().context("This tag doesn't have an asset attached")?;
    let url = asset.browser_download_url.clone();

    info!("Downloading: {}", &url);

    let c = Client::new();
    let mut stream = c.get(url).send().await?.bytes_stream();

    let dl_path = path.join(&format!("ghidra_{}.zip", rel.tag_name));
    debug!("DL path: {:?}", dl_path);

    info!("Saving to: {}", dl_path.as_path().display());

    if dl_path.exists() {
        info!("Using cached download");
    } else if !args.offline {
        let mut dl_file = tokio::fs::OpenOptions::default()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&dl_path)
            .await?;

        let pb = indicatif::ProgressBar::new(asset.size as _);
        while let Some(item) = stream.next().await {
            let item = &item?;
            dl_file.write(item).await?;
            pb.inc(item.len() as _);
        }
        pb.finish();
    } else {
        error!("Offline and no cached version found");
        return Ok(());
    }

    info!("Extracting");

    let reader = std::fs::File::open(&dl_path)?;
    let mut zip = match zip::ZipArchive::new(reader) {
        Ok(z) => z,
        Err(e) => {
            std::fs::remove_file(&dl_path)?;
            return Err(anyhow!("Could not open zip file, deleting: {e}"));
        }
    };
    zip.extract(path)?;

    let dir_name = {
        let file_name = dl_path.file_name().unwrap().to_str().unwrap();
        let parts = file_name.split("_").collect::<Vec<&str>>();
        let version = parts[2];
        format!("ghidra_{version}_PUBLIC")
    };
    let dir_path = dl_path.parent().unwrap().join(dir_name);
    std::fs::remove_file(&dl_path).context("Failed to delete zip")?;

    cacher.cache.entries.insert(tag.clone(), CacheEntry {
        path: dir_path,
    });
    cacher.save()?;

    Ok(())
}

//TODOS:
// plugins (install (all) / rm(all) )

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy())
        .init();

    let args = Args::parse();

    let home = std::env::home_dir().context("Couldn't determine home directory")?;
    let path = home.join(".local/opt/gvm/");
    let _ = std::fs::create_dir_all(&path);

    let cache_path = path.join("cache.toml");
    let mut cacher = Cacher::load(cache_path)?;

    update_latest_version(&mut cacher).await?;

    match &args.cmd {
        Cmd::Update => {
            if cacher.cache.default != "latest" {
                error!("Can't update when default is a fixed version");
                return Ok(());
            }

            let latest = cacher.cache.latest_known.clone();
            if !cacher.cache.entries.contains_key(latest.as_str()) {
                info!("✨✨✨ New version available: {latest} ✨✨✨");
                install_version(&mut cacher, &args, &path, &latest).await?;
            } else {
                info!("You have the latest version already!");
            }
        }
        Cmd::Default { cmd } => {
            match cmd {
                DefaultSubCmd::Show => {
                    info!("{}", cacher.cache.default);
                }
                DefaultSubCmd::Set { tag } => {
                    cacher.cache.default = tag.clone();
                    cacher.save()?;

                    if cacher.cache.entries.get(tag).is_none() {
                        install_version(&mut cacher, &args, &path, tag).await?;
                    }
                }
            }
        }
        Cmd::Uninstall { tag } => {
            let tag = match tag.as_str() {
                "default" => cacher.default_explicit(),
                "latest" => cacher.cache.latest_known.clone(),
                _ => tag.to_string(),
            };

            if let Some(cache_entry) = cacher.cache.entries.get(&tag) {
                std::fs::remove_dir_all(&cache_entry.path).context("Failed to delete directory")?;
                cacher.cache.entries.remove(&tag);
                cacher.save()?;
            } else {
                error!("That version isn't installed");
            }
        }
        Cmd::Run { tag } => {
            let tag = match tag {
                Some(tag) => tag.clone(),
                None => cacher.default_explicit(),
            };

            if !cacher.cache.entries.contains_key(&tag) {
                install_version(&mut cacher, &args, &path, &tag).await?;
            }

            let path = &cacher.cache.entries.get(&tag).as_ref().unwrap().path;
            let runner = path.join("ghidraRun");
            info!("Launching {}", runner.display());
            Command::new(&runner).spawn()?;
        }
        Cmd::Install { tag } => {
            install_version(&mut cacher, &args, &path, tag).await?;
        }
        Cmd::List => {
            let octocrab = octocrab::instance();

            // Returns the first page of all issues.
            let page = octocrab.repos("NationalSecurityAgency", "ghidra")
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
                    if cacher.cache.entries.contains_key(&c.tag_name) {
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
