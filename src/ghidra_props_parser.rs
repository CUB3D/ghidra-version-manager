use std::{
    collections::BTreeMap,
    path::Path,
};

use anyhow::Context;

#[derive(Debug)]
pub struct GhidraPropsFile {
    pub fields: BTreeMap<String, Vec<String>>,
}

impl GhidraPropsFile {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let mut out = BTreeMap::new();

        let data = std::fs::read_to_string(path)?;

        for line in data.lines() {
            if line.starts_with('#') {
                continue;
            }

            if line.contains('=') {
                let eq = line.chars().position(|c| c == '=').context("Missing eq")?;
                let key = &line[..eq];
                let val = &line[eq + 1..];

                out.entry(key.to_string())
                    .and_modify(|f: &mut Vec<String>| f.push(val.to_string()))
                    .or_insert(vec![val.to_string()]);
            }
        }

        Ok(Self { fields: out })
    }

    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, &self.generate_prop_content())?;
        Ok(())
    }

    fn generate_prop_content(&self) -> String {
        let mut out = String::new();

        for (key, vals) in self.fields.iter() {
            for val in vals {
                out.push_str(key);
                out.push('=');
                out.push_str(val);
                out.push('\n');
            }
        }

        out
    }

    pub fn get_by_key(&self, key: &str) -> Option<Vec<String>> {
        self.fields.get(key).cloned()
    }

    pub fn put(&mut self, key: &str, val: Vec<String>) {
        self.fields.insert(key.to_string(), val);
    }
}
