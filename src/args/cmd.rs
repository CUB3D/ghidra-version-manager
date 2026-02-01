use clap::Subcommand;
use crate::args::default_subcommand::DefaultSubCmd;
use crate::args::prefs_subcommand::PrefsSubCmd;
use crate::args::settings_subcommand::SettingsSubcommand;
use crate::extensions::ExtSubcommand;

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// List the available Ghidra versions
    #[command(alias = "ls")]
    List,

    /// Install a Ghidra version
    #[command(alias = "i")]
    Install {
        /// Which version to install
        tag: String,
    },

    /// Launch Ghidra, unless specified launches the default version
    #[command(alias = "r")]
    Run {
        /// Override the version to run
        tag: Option<String>,
    },

    /// Remove a Ghidra version
    #[command(alias = "del")]
    Uninstall {
        /// The version to remove
        tag: String,
    },

    /// Manage the default version
    Default {
        #[clap(subcommand)]
        cmd: DefaultSubCmd,
    },

    /// Manage preferences
    #[command(alias = "p")]
    Prefs {
        #[clap(subcommand)]
        cmd: PrefsSubCmd,
    },

    /// Update the default version
    #[command(alias = "u")]
    Update,

    /// Force update check
    #[command(alias = "U")]
    CheckUpdate,

    /// Manage extensions
    #[command(alias = "e")]
    Extensions {
        #[clap(subcommand)]
        cmd: ExtSubcommand,
    },

    /// Manage ghidra settings
    Settings {
        #[clap(subcommand)]
        cmd: SettingsSubcommand,
    },
}