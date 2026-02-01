use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GvmConfig {
    pub version: u32,
    pub tag: String,
}
