use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};
use crate::password_entry::PasswordEntry;

#[derive(Parser)]
#[command(name = "PWMan")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    pub username: String,
    pub password: String,
    #[arg(short = 'p', long = "profile", value_name = "FILE")]
    pub profile: PathBuf,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    Add(EntryArgs),
    Remove {
        site: String
    },
    Modify(EntryArgs),
}

#[derive(Args)]
pub(crate) struct EntryArgs {
    pub site: String,
    pub username: String,
    pub password: String,
}

impl From<PasswordEntry> for EntryArgs {
    fn from(value: PasswordEntry) -> Self {
        Self {
            site: value.site,
            username: value.username,
            password: value.password,
        }
    }
}
