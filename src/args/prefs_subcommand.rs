use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum PrefsSubCmd {
    /// Display the current prefs
    Show,

    /// Set the prefs
    Set {
        /// The key to set
        key: String,

        /// The new value
        value: String,
    },
}
