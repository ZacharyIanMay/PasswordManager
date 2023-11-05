
pub(crate) use anyhow::Result as Result;
use clap::Parser;
use crate::cli::{Cli, Commands, EntryArgs};
use crate::crypto_manager::CryptoManager;
use crate::manager::Manager;

mod manager;
mod crypto_manager;
mod password_entry;
mod cli;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut manager = Manager::new(&cli.profile);
    manager.verify_master_credentials(&cli.username, &cli.password)?;

    match cli.command {
        Commands::Add(EntryArgs { site, username, password }) => {
            manager.add_password(username, password, site)?;
        }
        Commands::Remove { site } => {
            manager.delete_password(site)?;
        }
        Commands::Modify(EntryArgs { site, username, password }) => {
            manager.update_password(site, username, password)?;
        }
    }

    manager.profile
           .expect("Profile is not set, this should not have happened")
           .save_file(cli.profile)
}

