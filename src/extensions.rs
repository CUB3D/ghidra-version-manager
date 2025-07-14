use crate::cache::ExtEntry;
use crate::{Args, Cacher};
use anyhow::Context;
use anyhow::anyhow;
use clap::Subcommand;
use flate2::bufread::GzDecoder;
use futures_util::Stream;
use futures_util::StreamExt;
use include_directory::{Dir, include_directory};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use tar::{Archive, EntryType};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

static EXTENSIONS: Dir = include_directory!("./extensions-repo");

#[derive(Serialize, Deserialize, Debug)]
pub enum ExtKind {
    /// Only download latest releases
    DownloadOnly,

    /// A processor module that should be cloned directly
    ProcessorGit,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ExtDef {
    /// The name of the module
    pub name: String,

    /// The GitHub user to pull from
    pub repo_user: String,

    /// The GitHub repo to pull from
    pub repo_repo: String,

    /// Unique id for extension
    pub slug: String,

    /// The type of module
    pub kind: ExtKind,

    /// For git processor modules should the root files in the git be taken as the root of the module
    /// This will create Processors/<name>/<git contents> directly
    /// Without this we assume that the git stores /<name>/<module> and install <module> to Processors/<name>/
    /// With this we assume that the git stores /<module> and install <module> to Processors/<name>/
    pub no_prefix: Option<bool>,

    /// Which branch to checkout for git modules
    pub branch_name: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum ExtSubcommand {
    #[command(alias = "ls")]
    /// List known extensions
    List,

    #[command(alias = "i")]
    /// List known extensions
    Install {
        /// The extension to install
        name: String,

        /// The version to install it to
        ghidra_version: Option<String>,
    },

    #[command(alias = "rm")]
    /// Remove an extension
    Uninstall {
        /// The extension to remove
        name: String,

        /// The version to remove it from
        ghidra_version: Option<String>,
    },
}

pub fn find_by_name(name: &str) -> anyhow::Result<ExtDef> {
    for e in EXTENSIONS.entries() {
        let entry = toml::from_slice::<ExtDef>(e.as_file().unwrap().contents())?;
        if entry.name.to_lowercase() == name.to_lowercase() {
            return Ok(entry);
        }
    }

    Err(anyhow!("Failed to find {name}"))
}

pub(crate) async fn handle_ext_cmd(
    cacher: &mut Cacher,
    path: &Path,
    _args: &Args,
    cmd: &ExtSubcommand,
) -> anyhow::Result<()> {
    match cmd {
        ExtSubcommand::Uninstall {
            name,
            ghidra_version,
        } => {
            let ghidra_version = ghidra_version.clone().unwrap_or(cacher.default_explicit());
            let ext_def = find_by_name(name)?;

            let ent = cacher.cache.entries.get_mut(&ghidra_version).unwrap();
            let ext = ent.extensions.get(&ext_def.slug).cloned().unwrap();
            ent.extensions.remove(&ext_def.slug);
            cacher.save()?;

            for f in &ext.files {
                if std::fs::exists(f).unwrap_or(false) {
                    if std::fs::metadata(f)?.is_file() {
                        info!("rm {}", f.display());
                        let _ = std::fs::remove_file(f);
                    } else {
                        info!("rmdir {}", f.display());
                        let _ = std::fs::remove_dir_all(f);
                    }
                }
            }
        }
        ExtSubcommand::Install {
            name,
            ghidra_version,
        } => {
            let ghidra_version = ghidra_version.clone().unwrap_or(cacher.default_explicit());

            if !cacher.is_installed(&ghidra_version) {
                error!("Version '{ghidra_version}' isn't installed!");
                return Ok(());
            }

            let entry = find_by_name(name)?;

            let ghidra_ent = cacher.cache.entries.get(&ghidra_version).unwrap();
            if ghidra_ent.extensions.contains_key(&entry.slug) {
                error!("That extension is already installed");
                return Ok(());
            }

            match entry.kind {
                ExtKind::DownloadOnly => {
                    info!("Installing download only extension");
                    let octocrab = octocrab::instance();

                    let rel = octocrab
                        .repos(entry.repo_user, entry.repo_repo)
                        .releases()
                        .get_latest()
                        .await?;

                    let asset = rel
                        .assets
                        .first()
                        .context("This tag doesn't have an asset attached")?;
                    let url = asset.browser_download_url.clone();

                    info!("Downloading: {} -> {}", &url, asset.name);

                    let c = Client::new();
                    let mut stream = c.get(url).send().await?.bytes_stream();

                    let dl_path = path.join(asset.name.as_str());
                    debug!("DL path: {:?}", dl_path);

                    info!("Saving to: {}", dl_path.as_path().display());

                    let mut dl_file = tokio::fs::OpenOptions::default()
                        .write(true)
                        .truncate(true)
                        .create(true)
                        .open(&dl_path)
                        .await?;

                    let pb = indicatif::ProgressBar::new(asset.size as _);
                    while let Some(item) = stream.next().await {
                        let item = &item?;
                        dl_file.write_all(item).await?;
                        pb.inc(item.len() as _);
                    }
                    pb.finish();

                    info!(
                        "This extension requires manual installation, please install using File->Install Extensions and select:"
                    );
                    info!("{}", dl_path.as_path().display());

                    cacher.with_cache(|c| {
                        let ent = c.entries.get_mut(&ghidra_version).unwrap();
                        ent.extensions.insert(
                            entry.slug,
                            ExtEntry {
                                files: vec![dl_path],
                            },
                        );
                    })?;
                }
                ExtKind::ProcessorGit => {
                    info!("Installing git processor extension");
                    let url = Url::parse(&format!(
                        "https://api.github.com/repos/{}/{}/tarball/{}",
                        entry.repo_user,
                        entry.repo_repo,
                        entry.branch_name.unwrap_or("master".to_string())
                    ))?;

                    let dl_path = path.join(format!("{}.tar.gz", entry.slug));
                    debug!("DL path: {:?}", dl_path);

                    info!("Saving to: {}", dl_path.as_path().display());

                    let c = Client::default();
                    let mut stream = c
                        .get(url)
                        .header("User-Agent", "octocrab")
                        .send()
                        .await?
                        .bytes_stream();

                    let mut dl_file = tokio::fs::OpenOptions::default()
                        .write(true)
                        .truncate(true)
                        .create(true)
                        .open(&dl_path)
                        .await?;

                    let pb = indicatif::ProgressBar::new(stream.size_hint().0 as u64);
                    while let Some(item) = stream.next().await {
                        let item = &item?;
                        dl_file.write_all(item).await?;
                        pb.inc(item.len() as _);
                    }
                    pb.finish();

                    info!("Download done");

                    // dec
                    let bytes = std::fs::read(dl_path)?;
                    let d = GzDecoder::new(&*bytes);

                    let mut a = Archive::new(d);

                    let cache_ent = match cacher.cache.entries.get(&ghidra_version) {
                        Some(e) => e,
                        None => {
                            error!("Version {ghidra_version} isn't known");
                            return Err(anyhow!("Failed to fetch version"));
                        }
                    };

                    let base = cache_ent.path.clone();
                    let base = base.join("Ghidra/Processors");

                    // let root = a.entries().it

                    info!("Extracting");

                    let mut tmp = "".to_string();

                    let mut ext = ExtEntry::default();
                    ext.files.push(base.join(&entry.name));
                    info!("files: {:?}", ext.files);

                    for file in a.entries()? {
                        let mut file = file?;
                        let out_path = file.header().path()?;

                        if tmp.is_empty() {
                            if entry.no_prefix.unwrap_or_default() {
                                if file.header().entry_type() == EntryType::Directory {
                                    tmp = out_path.to_string_lossy().to_string();
                                }
                            } else if out_path.ends_with(format!("{}/", entry.name)) {
                                tmp = out_path.to_string_lossy().to_string();
                            }

                            continue;
                        }

                        // println!("ext {:?}", out_path);

                        if file.header().entry_type() == EntryType::Regular {
                            let out_path = file.header().path()?;
                            let out_path = out_path.to_string_lossy().to_string();
                            if !out_path.starts_with(&tmp) {
                                continue;
                            }
                            let out_path =
                                out_path.replace(&tmp, &format!("{}/", entry.name.as_str()));
                            let out_path = base.join(&out_path);

                            let _ = std::fs::create_dir_all(out_path.parent().unwrap());

                            let mut out = Vec::new();
                            file.read_to_end(&mut out)?;
                            std::fs::write(&out_path, &out)?;

                            info!("{}", out_path.display());

                            ext.files.push(out_path);
                        }
                    }

                    cacher.with_cache(|c| {
                        let ent = c.entries.get_mut(&ghidra_version).unwrap();
                        ent.extensions.insert(entry.slug, ext);
                    })?;
                }
            }

            return Ok(());
        }

        ExtSubcommand::List => {
            info!("Known extensions:");
            for e in EXTENSIONS.entries() {
                let entry = toml::from_slice::<ExtDef>(e.as_file().unwrap().contents())?;
                info!("- {}", entry.name);
            }
        }
    }

    Ok(())
}
