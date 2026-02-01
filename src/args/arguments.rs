use crate::args::cmd::Cmd;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Cmd,

    /// Enable expanded logging
    #[arg(short, long, default_value = "false")]
    pub verbose: bool,

    /// Disable network access
    #[arg(short, long, default_value = "false")]
    pub offline: bool,

    /// Run in launcher mode
    #[arg(short, long, default_value = "false")]
    pub launcher: bool,
}
