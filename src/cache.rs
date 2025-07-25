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

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Prefs {
    pub pyghidra: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Cache {
    pub entries: HashMap<String, CacheEntry>,
    pub default: String,
    pub latest_known: String,
    pub last_update_check: DateTime<Utc>,
    #[serde(default)]
    pub prefs: Prefs,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            entries: Default::default(),
            default: "latest".to_string(),
            latest_known: "".to_string(),
            last_update_check: Utc::now(),
            prefs: Prefs::default(),
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
            match std::fs::read_to_string(&cache_path)
                .context("Failed to read cache data")
                .and_then(|s| toml::from_str(&s).context("Failed to parse cache data"))
            {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to load old cache {e}");
                    Cache::default()
                }
            }
        };

        Ok(Self {
            cache: cache_data,
            cache_path,
        })
    }

    pub fn with_cache(&mut self, f: impl FnOnce(&mut Cache)) -> anyhow::Result<()> {
        f(&mut self.cache);
        self.save()?;
        Ok(())
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let s = toml::to_string(&self.cache)?;
        std::fs::write(&self.cache_path, &s).context("Failed to write cache data")?;
        Ok(())
    }

    pub fn default_explicit(&self) -> String {
        match self.cache.default.as_str() {
            "latest" => self.cache.latest_known.clone(),
            _ => self.cache.default.clone(),
        }
    }

    pub fn is_installed(&self, tag: &str) -> bool {
        self.cache.entries.contains_key(tag)
    }
}
