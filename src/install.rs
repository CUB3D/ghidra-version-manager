use crate::{
    Args,
    cache::{CacheEntry, Cacher},
};
use anyhow::Context;
use anyhow::anyhow;
use futures_util::StreamExt;
use ico::IconDir;
use reqwest::Client;
use std::fs::{File, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use std::{env::home_dir, path::PathBuf};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

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

    let c = Client::builder()
        .gzip(true)
        .deflate(true)
        .zstd(true)
        .brotli(true)
        .timeout(Duration::from_secs(45))
        .build()?;

    let mut stream = c.get(url).send().await?.bytes_stream();

    let dl_path = path.join(format!("ghidra_{}.zip", rel.tag_name));
    debug!("DL path  {:?}", dl_path);

    info!("Saving to {}", dl_path.as_path().display());

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
            let item = item?;
            dl_file.write_all(&item).await?;
            pb.inc(item.len() as _);
        }
        pb.finish();
    } else {
        error!("Offline and no cached version found");
        return Ok(());
    }

    info!("Extracting to {}", path.display());

    let reader = File::open(&dl_path)?;
    let mut zip = match zip::ZipArchive::new(reader) {
        Ok(z) => z,
        Err(e) => {
            std::fs::remove_file(&dl_path)?;
            return Err(anyhow!("Could not open zip file, deleting: {e}"));
        }
    };
    match zip.extract(path) {
        Ok(_) => {}
        Err(e) => {
            std::fs::remove_file(&dl_path)?;
            return Err(anyhow!("Could not extract zip file, deleting: {e}"));
        }
    }

    info!("Creating application launcher entries");

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

    let exec = dir_path.join("ghidraRun").to_string_lossy().to_string();
    let ico = dir_path
        .join("support/ghidra.ico")
        .to_string_lossy()
        .to_string();

    // Create desktop entries on linux
    let desktop = if cfg!(target_os = "linux") {
        let app_dir = home_dir().unwrap().join(".local/share/applications/");
        let _ = std::fs::create_dir_all(&app_dir);
        let desktop = app_dir.join(format!("ghidra_{version}.desktop"));

        let mut entry = "[Desktop Entry]\n".to_string();
        entry.push_str(&format!("Name=Ghidra ({version})\n"));
        entry.push_str("Comment=Ghidra\n");
        entry.push_str(&format!("Exec={exec}\n"));
        entry.push_str(&format!("Icon={ico}\n"));
        std::fs::write(&desktop, entry)?;

        Some(desktop)
    } else if cfg!(target_os = "macos") {
        let base = PathBuf::from("/Applications");
        let name = format!("Ghidra_{version}");
        let app = base.join(format!("{name}.app"));
        std::fs::create_dir_all(&app)?;
        let bin = app.join(&name);
        let mut script = "#!/bin/sh -i\n".to_string();
        script.push_str("/Users/cub3d/.local/opt/gvm/ghidra_9.0.1/ghidraRun");
        std::fs::write(&bin, script).expect("Failed to write to script file");
        std::fs::set_permissions(bin, Permissions::from_mode(0o744))?;

        let cont = app.join("Contents");
        let res = cont.join("Resources");
        std::fs::create_dir_all(&res)?;
        let info = cont.join("Info.plist");
        let res = res.join("Icon.png");

        let plist = include_str!("../res/macos_plist.plist")
            .to_string()
            .replace("{name}", &name)
            .replace("{version}", version);

        std::fs::write(&info, plist.as_bytes()).expect("Failed to write to script file");

        let ico_file = File::open(&ico)?;
        let ico = IconDir::read(ico_file)?;
        let image = ico.entries()[0].decode()?;

        let file = File::create(res)?;
        image.write_png(&file)?;

        Some(app)
    } else {
        None
    };

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

    std::fs::remove_file(&dl_path).context("Failed to delete zip")?;

    Ok(())
}
