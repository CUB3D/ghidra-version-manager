use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum DefaultSubCmd {
    /// Display the current Ghidra version
    Show,

    /// Set the default version, installing it if needed
    Set { tag: String },
}
