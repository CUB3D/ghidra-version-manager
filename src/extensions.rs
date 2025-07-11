use crate::{Args, Cacher};
use anyhow::Context;
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
use tracing::{debug, info};

static EXTENSIONS: Dir = include_directory!("./extensions-repo");

#[derive(Serialize, Deserialize, Debug)]
pub enum ExtKind {
    DownloadOnly,
    ProcessorGit,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ExtDef {
    pub name: String,
    pub repo_user: String,
    pub repo_repo: String,
    pub slug: String,
    pub kind: ExtKind,
}

#[derive(Debug, Subcommand)]
pub enum ExtSubcommand {
    /// List known extensions
    List,

    /// List known extensions
    Install {
        /// The extension to install
        name: String,

        /// The version to install it to
        ghidra_version: Option<String>,
    },
}

pub(crate) async fn handle_ext_cmd(
    cacher: &mut Cacher,
    path: &Path,
    _args: &Args,
    cmd: &ExtSubcommand,
) -> anyhow::Result<()> {
    match cmd {
        ExtSubcommand::Install {
            name,
            ghidra_version,
        } => {
            let ghidra_version = ghidra_version.clone().unwrap_or(cacher.default_explicit());

            for e in EXTENSIONS.entries() {
                let entry = toml::from_slice::<ExtDef>(e.as_file().unwrap().contents())?;
                if entry.name.as_str() == name.as_str() {
                    match entry.kind {
                        ExtKind::DownloadOnly => {
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
                        }
                        ExtKind::ProcessorGit => {
                            let url = Url::parse(&format!(
                                "https://api.github.com/repos/{}/{}/tarball/master",
                                entry.repo_user, entry.repo_repo
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

                            let base = cacher
                                .cache
                                .entries
                                .get(&ghidra_version)
                                .unwrap()
                                .path
                                .clone();
                            let base = base.join("Ghidra/Processors");

                            // let root = a.entries().it

                            info!("Extracting");

                            let mut tmp = "".to_string();

                            for file in a.entries()? {
                                let mut file = file?;
                                let out_path = file.header().path()?;
                                if out_path.ends_with(format!("{}/", entry.name)) {
                                    tmp = out_path.to_string_lossy().to_string();
                                }

                                if tmp.is_empty() {
                                    continue;
                                }

                                // println!("{:?}", tmp);

                                if file.header().entry_type() == EntryType::Regular {
                                    let out_path = file.header().path()?;
                                    let out_path = out_path.to_string_lossy().to_string();
                                    if !out_path.starts_with(&tmp) {
                                        continue;
                                    }
                                    let out_path = out_path
                                        .replace(&tmp, &format!("{}/", entry.name.as_str()));
                                    let out_path = base.join(&out_path);

                                    let _ = std::fs::create_dir_all(out_path.parent().unwrap());

                                    let mut out = Vec::new();
                                    file.read_to_end(&mut out)?;
                                    std::fs::write(&out_path, &out)?;

                                    info!("{}", out_path.display());
                                }
                            }
                        }
                    }

                    return Ok(());
                }
            }
        }
        ExtSubcommand::List => {
            info!("Known extensions:");
            for e in EXTENSIONS.entries() {
                let entry = toml::from_slice::<ExtDef>(e.as_file().unwrap().contents()).unwrap();
                info!("- {}", entry.name);
            }
        }
    }

    Ok(())
}
