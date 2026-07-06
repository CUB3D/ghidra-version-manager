use crate::cache::CacheEntry;
use crate::prefs_backup::gvm_config::GvmConfig;
use anyhow::Context;
use std::io::{Cursor, Read};
use std::path::Path;
use std::path::PathBuf;
use tracing::info;
use zip::ZipArchive;

pub struct BackupRestorer {
    pub backup_data: Vec<u8>,
}

impl BackupRestorer {
    pub fn from_path(p: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            backup_data: std::fs::read(p)?,
        })
    }
    pub fn restore_to_cached_version(&self, cache_entry: &CacheEntry) -> anyhow::Result<()> {
        let pref_path = cache_entry
            .preferences_path()
            .context("Failed to get preferences path")?;

        let zip_data = Cursor::new(&self.backup_data);
        let mut zip = ZipArchive::new(zip_data)?;

        let root = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
        let prefs = root.join("prefs");
        let mut prefs = zip.by_path(prefs).context("Prefs not found")?;
        let mut prefs_data = Vec::new();
        prefs
            .read_to_end(&mut prefs_data)
            .context("Failed to read backup file")?;
        drop(prefs);

        let cfg_path = root.join("gvm_config.toml");
        let mut cfg = zip.by_path(&cfg_path).context("Config not found")?;
        let mut cfg_data = Vec::new();
        cfg.read_to_end(&mut cfg_data).context(format!(
            "Failed to read '{}' from backup archive",
            cfg_path.display()
        ))?;
        let cfg =
            toml::from_slice::<GvmConfig>(&cfg_data).context("Failed to parse gvm_config.toml")?;

        info!("Restoring backup version {} from {}", cfg.version, cfg.tag);

        // If you haven't launched the new version (e.g. this is an auto restore to a newly installed version)
        // Then the config path won't exist yet
        if !pref_path.exists() {
            info!("This version hasn't been launched before, creating directories");
            std::fs::create_dir_all(pref_path.parent().unwrap())
                .context("Failed to create directories")?;
        }

        std::fs::write(pref_path, prefs_data).context("Failed to write preferences file")?;

        Ok(())
    }
}
