use crate::cache::CacheEntry;
use crate::prefs_backup::gvm_config::GvmConfig;
use anyhow::Context;
use std::io::{Cursor, Read};
use std::path::Path;
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
        let home = std::env::home_dir().context("Couldn't determine home directory")?;

        let name = cache_entry.path.file_name().unwrap();
        let pref_path = home
            .join("./.config/ghidra/")
            .join(name)
            .join("./preferences");

        let zip_data = Cursor::new(&self.backup_data);
        let mut zip = ZipArchive::new(zip_data)?;

        let mut prefs = zip.by_path("/prefs").context("Prefs not found")?;
        let mut prefs_data = Vec::new();
        prefs.read_to_end(&mut prefs_data)?;
        drop(prefs);

        let mut cfg = zip
            .by_path("/gvm_config.toml")
            .context("Config not found")?;
        let mut cfg_data = Vec::new();
        cfg.read_to_end(&mut cfg_data)?;
        let cfg = toml::from_slice::<GvmConfig>(&cfg_data)?;

        info!("Restoring backup version {} from {}", cfg.version, cfg.tag);

        std::fs::write(pref_path, prefs_data)?;

        Ok(())
    }
}
