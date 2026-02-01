use crate::cache::CacheEntry;
use crate::prefs_backup::backup_restorer::BackupRestorer;
use crate::prefs_backup::gvm_config::GvmConfig;
use anyhow::Context;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub struct BackupGenerator {
    pub backup_data: Vec<u8>,
}

impl BackupGenerator {
    pub fn from_cached_version(cache_entry: &CacheEntry, tag: &str) -> anyhow::Result<Self> {
        let home = std::env::home_dir().context("Couldn't determine home directory")?;

        let name = cache_entry.path.file_name().unwrap();
        let pref_path = home
            .join("./.config/ghidra/")
            .join(name)
            .join("./preferences");
        let prefs_data = std::fs::read(&pref_path).context("Failed to read ghidra prefs")?;

        let mut zip_out = Cursor::new(Vec::new());
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let mut zip = ZipWriter::new(&mut zip_out);
        zip.start_file("prefs", options)?;
        zip.write_all(&prefs_data)?;

        zip.start_file("gvm_config.toml", options)?;
        zip.write_all(
            toml::to_string(&GvmConfig {
                version: 0,
                tag: tag.to_string(),
            })?
            .as_bytes(),
        )?;

        zip.finish()?;

        Ok(Self {
            backup_data: zip_out.into_inner(),
        })
    }

    pub fn restorer(self) -> BackupRestorer {
        BackupRestorer {
            backup_data: self.backup_data,
        }
    }
}
