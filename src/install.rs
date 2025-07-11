use std::{env::home_dir, path::PathBuf};

use anyhow::Context;
use anyhow::anyhow;
use futures_util::StreamExt;
use reqwest::Client;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

use crate::{
    Args,
    cache::{CacheEntry, Cacher},
};

pub async fn install_version(
    cacher: &mut Cacher,
    args: &Args,
    path: &PathBuf,
    tag: &String,
) -> anyhow::Result<()> {
    if cacher.cache.entries.contains_key(tag) {
        info!("That version is already installed");
        return Ok(());
    }

    let tag = match tag.as_str() {
        "default" => cacher.default_explicit(),
        "latest" => cacher.cache.latest_known.clone(),
        _ => tag.to_string(),
    };

    let octocrab = octocrab::instance();

    let rel = octocrab
        .repos("NationalSecurityAgency", "ghidra")
        .releases()
        .get_by_tag(&tag)
        .await?;

    let asset = rel
        .assets
        .first()
        .context("This tag doesn't have an asset attached")?;
    let url = asset.browser_download_url.clone();

    info!("Downloading: {}", &url);

    let c = Client::new();
    let mut stream = c.get(url).send().await?.bytes_stream();

    let dl_path = path.join(format!("ghidra_{}.zip", rel.tag_name));
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
            dl_file.write_all(item).await?;
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

    let file_name = dl_path.file_name().unwrap().to_str().unwrap();
    let parts = file_name.split("_").collect::<Vec<&str>>();
    let version = parts[2];
    let dir_name = format!("ghidra_{version}_PUBLIC");

    let mut dir_path = dl_path.parent().unwrap().join(dir_name);
    if !dir_path.exists() {
        info!("Failed to find extract, trying old style without suffix");
        let dir_name = format!("ghidra_{version}");

        dir_path = dl_path.parent().unwrap().join(dir_name);
    }

    std::fs::remove_file(&dl_path).context("Failed to delete zip")?;

    let exec = dir_path.join("ghidraRun").to_string_lossy().to_string();
    let ico = dir_path
        .join("support/ghidra.ico")
        .to_string_lossy()
        .to_string();

    let desktop = home_dir()
        .unwrap()
        .join(".local/share/applications/")
        .join(format!("ghidra_{version}.desktop"));

    let mut entry = "[Desktop Entry]\n".to_string();
    entry.push_str(&format!("Name=Ghidra ({version})\n"));
    entry.push_str("Comment=Ghidra\n");
    entry.push_str(&format!("Exec={exec}\n"));
    entry.push_str(&format!("Icon={ico}\n"));
    std::fs::write(&desktop, entry)?;

    cacher.with_cache(|c| {
        c.entries.insert(
            tag.clone(),
            CacheEntry {
                path: dir_path,
                launcher: desktop,
                extensions: Default::default(),
            },
        );
    })?;

    Ok(())
}
