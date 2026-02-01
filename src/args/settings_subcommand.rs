use std::path::PathBuf;
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum SettingsSubcommand {
    /// Export your current settings
    Backup {
        /// The destination
        out: PathBuf,

        /// The version to export
        tag: Option<String>,
    },

    /// Restore a prior backup
    Restore {
        /// The backup
        src: PathBuf,

        /// The version to restore to
        tag: Option<String>,
    },
}