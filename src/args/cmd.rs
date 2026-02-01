use clap::Subcommand;
use crate::args::default_subcommand::DefaultSubCmd;
use crate::args::prefs_subcommand::PrefsSubCmd;
use crate::extensions::ExtSubcommand;

#[derive(Debug, Subcommand)]
pub enum Cmd {
    #[command(alias = "ls")]
    /// List the available Ghidra versions
    List,

    #[command(alias = "i")]
    /// Install a Ghidra version
    Install { tag: String },

    #[command(alias = "r")]
    /// Launch Ghidra, unless specified launches the default version
    Run { tag: Option<String> },

    #[command(alias = "del")]
    /// Remove a Ghidra version
    Uninstall { tag: String },

    /// Manage the default version
    Default {
        #[clap(subcommand)]
        cmd: DefaultSubCmd,
    },

    /// Manage preferences
    Prefs {
        #[clap(subcommand)]
        cmd: PrefsSubCmd,
    },

    #[command(alias = "u")]
    /// Update the default version
    Update,

    /// Force update check
    CheckUpdate,

    #[command(alias = "e")]
    /// Manage extensions
    Extensions {
        #[clap(subcommand)]
        cmd: ExtSubcommand,
    },
}