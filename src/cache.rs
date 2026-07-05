//! Manages the cache.toml, tracking config and what versions are installed

use std::{collections::HashMap, path::PathBuf};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct ExtEntry {
    pub files: Vec<PathBuf>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct CacheEntry {
    pub path: PathBuf,
    pub launcher: Option<PathBuf>,
    pub extensions: HashMap<String, ExtEntry>,
}

impl CacheEntry {
    /// Get the path to the `preferences` file in the Ghidra config directory
    /// On linux this is in `~/.config/ghidra/<version>/preferences`
    /// On macOS this is in `~/Library/ghidra/<version>/preferences
    /// On Windows this is in TODO
    pub fn preferences_path(&self) -> anyhow::Result<PathBuf> {
        let home = std::env::home_dir().context("Couldn't determine home directory")?;

        let name = self.path.file_name().unwrap();

        let pref_path = if cfg!(target_os = "linux") {
            home.join("./.config/ghidra/")
                .join(name)
                .join("./preferences")
        } else if cfg!(target_os = "macos") {
            home.join("./Library/ghidra/")
                .join(name)
                .join("./preferences")
        } else {
            return Err(anyhow::anyhow!(
                "Sorry but we don't know how to backup settings on this platform yet"
            ));
        };

        Ok(pref_path)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Prefs {
    pub pyghidra: bool,

    pub ui_scale_override: u32,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            pyghidra: false,
            ui_scale_override: 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Cache {
    pub entries: HashMap<String, CacheEntry>,
    pub default: String,
    pub latest_known: String,
    pub last_update_check: DateTime<Utc>,
    #[serde(default)]
    pub prefs: Prefs,
    #[serde(default)]
    pub last_launched: String,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            default: "latest".to_string(),
            latest_known: String::new(),
            last_update_check: Utc::now(),
            prefs: Prefs::default(),
            last_launched: String::new(),
        }
    }
}

pub struct Cacher {
    pub cache: Cache,
    pub cache_path: PathBuf,
}

impl Cacher {
    pub fn load(cache_path: PathBuf) -> anyhow::Result<Self> {
        let cache_data = if !std::fs::exists(&cache_path).unwrap_or(false) {
            info!("No cache found, it will be created");
            Cache::default()
        } else {
            std::fs::read_to_string(&cache_path)
                .context("Failed to read cache data")
                .and_then(|s| toml::from_str(&s).context("Failed to parse cache data"))
                .unwrap_or_else(|e| {
                    error!("Failed to load old cache {e}");
                    Cache::default()
                })
        };

        Ok(Self {
            cache: cache_data,
            cache_path,
        })
    }

    pub fn with_cache(&mut self, f: impl FnOnce(&mut Cache)) -> anyhow::Result<()> {
        f(&mut self.cache);
        self.save().context("Failed to save cache")?;
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let s = toml::to_string(&self.cache).context("Failed to serialize cache data")?;
        std::fs::write(&self.cache_path, &s).context("Failed to write cache data")?;
        Ok(())
    }

    #[must_use]
    pub fn default_explicit(&self) -> String {
        match self.cache.default.as_str() {
            "latest" => self.cache.latest_known.clone(),
            _ => self.cache.default.clone(),
        }
    }

    #[must_use]
    pub fn is_installed(&self, tag: &str) -> bool {
        self.cache.entries.contains_key(tag)
    }
}
