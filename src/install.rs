use crate::{
    Args,
    cache::{CacheEntry, Cacher},
};
use anyhow::Context;
use anyhow::anyhow;
use futures_util::StreamExt;
use ico::IconDir;
use reqwest::Client;
use std::{collections::HashMap, time::Duration};
use std::{env::home_dir, path::PathBuf};
use std::{fs::File, process::Command};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};
use std::fmt::Write;

pub fn do_java_check() {
    //TODO: check java version compat
    let res = Command::new("javac").arg("--version").output();
    if let Ok(res) = res
        && res.status.success()
    {
        return;
    }

    error!("------------------------------");
    error!("You need to have the Java JDK (not JRE) installed to use Ghidra.");
    error!(
        "We tried to run `javac --version` but it failed, consider installing JDK (for Ghidra 11+ use version 21) LTS from the following:"
    );
    if cfg!(target_family = "windows") {
        error!("https://adoptium.net/temurin/releases");
    } else if cfg!(target_os = "macos") {
        error!("brew install openjdk@21");
    } else if cfg!(target_os = "linux") {
        error!("sudo apt install default-jdk (Debian/Ubuntu)");
        error!("sudo pacman -Sy jdk21-openjdk (Arch)");
        error!("sudo dnf install java-21-openjdk-devel (Fedora/RHEL/Rocky)");
        error!("sudo rpm-ostree install java-21-openjdk-devel (Fedora Silverblue/Kinoite)");
    } else {
        error!("I have no clue what platform you're on, try your platforms docs");
    }
    error!("------------------------------");
}

/// Installs a copy of Ghidra
/// - Finds the correct zip from GitHub releases
/// - Downloads it
/// - Extracts it
/// - Creates a .desktop file (linux)
/// - Creates a launcher in /Applications (macOS)
pub async fn install_version(
    cacher: &mut Cacher,
    args: &Args,
    path: &PathBuf,
    tag: &String,
) -> anyhow::Result<()> {
    do_java_check();

    debug!("Installing tag '{tag}'");
    if cacher.cache.entries.contains_key(tag) {
        info!("That version is already installed");
        return Ok(());
    }

    let tag = match tag.as_str() {
        "default" => cacher.default_explicit(),
        "latest" => cacher.cache.latest_known.clone(),
        _ => tag.to_string(),
    };
    debug!("Installing actual tag '{tag}'");

    let octocrab = octocrab::instance();

    let release = octocrab
        .repos("NationalSecurityAgency", "ghidra")
        .releases()
        .get_by_tag(&tag)
        .await?;

    let asset = release
        .assets
        .first()
        .context("This tag doesn't have an asset attached")?;
    let url = asset.browser_download_url.clone();

    info!("⬇️ Downloading: {}", &url);

    let c = Client::builder()
        .gzip(true)
        .deflate(true)
        .zstd(true)
        .brotli(true)
        .timeout(Duration::from_secs(300))
        .build()?;

    let mut stream = c.get(url).send().await?.bytes_stream();

    let dl_path = path.join(format!("ghidra_{}.zip", release.tag_name));

    info!("💾 Saving to {}", dl_path.as_path().display());

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

    info!("📦 Extracting to {}", path.display());

    let reader = File::open(&dl_path)?;
    let mut zip = match zip::ZipArchive::new(reader) {
        Ok(z) => z,
        Err(e) => {
            std::fs::remove_file(&dl_path)?;
            return Err(anyhow!("Could not open zip file, deleting: {e}"));
        }
    };
    match zip.extract(path) {
        Ok(()) => {}
        Err(e) => {
            std::fs::remove_file(&dl_path)?;
            return Err(anyhow!("Could not extract zip file, deleting: {e}"));
        }
    }

    info!("⚙️ Creating application launcher entries");

    let file_name = dl_path.file_name().unwrap().to_str().unwrap();
    let parts = file_name.split('_').collect::<Vec<&str>>();
    let version = parts[2];
    let dir_name = format!("ghidra_{version}_PUBLIC");

    let mut dir_path = dl_path.parent().unwrap().join(dir_name);
    if !dir_path.exists() {
        info!("Failed to find extract, trying old style without suffix");
        let dir_name = format!("ghidra_{version}");

        dir_path = dl_path.parent().unwrap().join(dir_name);
    }

    let us = std::env::current_exe()?;

    let exec = format!("{} --launcher run {tag}", us.to_string_lossy());

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
        let _ = writeln!(entry, "Name=Ghidra ({version})");
        entry.push_str("Comment=Ghidra\n");
        let _ = writeln!(entry, "Exec={exec}");
        let _ = writeln!(entry, "Icon={ico}");
        entry.push_str("Type=Application\n");
        entry.push_str("Categories=Development\n");
        entry.push_str("StartupWMClass=ghidra-Ghidra\n");
        std::fs::write(&desktop, entry)?;

        Some(desktop)
    } else if cfg!(target_os = "macos") {
        let base = PathBuf::from("/Applications");
        let name = format!("Ghidra_{version}");
        let app = base.join(format!("{name}.app"));
        std::fs::create_dir_all(&app)?;
        let bin = app.join(&name);
        let mut script = "#!/bin/sh -i\n".to_string();
        script.push_str(&exec);
        std::fs::write(&bin, script).expect("Failed to write to script file");

        // On unixes we need to mark the binary as executable
        #[cfg(target_os = "macos")]
        {
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(bin, Permissions::from_mode(0o744))?;
        }

        let cont = app.join("Contents");
        let resource_dir = cont.join("Resources");
        std::fs::create_dir_all(&resource_dir)?;
        let info = cont.join("Info.plist");
        let icon_path = resource_dir.join("Icon.png");

        let plist = include_str!("../res/macos_plist.plist")
            .to_string()
            .replace("{name}", &name)
            .replace("{version}", version);

        std::fs::write(&info, plist.as_bytes()).expect("Failed to write to script file");

        let ico_file = File::open(&ico)?;
        let ico = IconDir::read(ico_file)?;
        let image = ico.entries()[0].decode()?;

        let file = File::create(icon_path)?;
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
                extensions: HashMap::new(),
            },
        );
    })?;

    std::fs::remove_file(&dl_path).context("Failed to delete zip")?;

    Ok(())
}
