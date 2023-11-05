pub(crate) use anyhow::Result as Result;
use clap::Parser;
use flexi_logger::Logger;
use crate::cli::{Cli, Commands, EntryArgs};
use crate::crypto_manager::CryptoManager;
use crate::manager::Manager;

mod manager;
mod crypto_manager;
mod password_entry;
mod cli;

fn main() -> Result<()> {
    Logger::try_with_env_or_str("error")?.start()?;
    let cli = Cli::parse();

    let mut manager = Manager::new(&cli.profile);
    manager.verify_master_credentials(&cli.username, &cli.password)?;

    match cli.command {
        Commands::Add(EntryArgs { site, username, password }) => {
            manager.add_password(username, password, site)?;
            println!("Password added");
        }
        Commands::Remove { site } => {
            manager.delete_password(site)?;
            println!("Password removed");
        }
        Commands::Modify(EntryArgs { site, username, password }) => {
            manager.update_password(site, username, password)?;
            println!("Password updated");
        }
        Commands::Get { site } => {
            if let Some(site) = site {
                let entry = manager.get_password(site)?;
                println!("Password found");
                println!("\tSITE:USERNAME:PASSWORD");
                println!("\t|    {entry}");
            } else {
                let entries = manager.retrieve_entries()?;
                println!("Passwords");
                println!("\tSITE:USERNAME:PASSWORD");
                for entry in entries {
                    println!("\t|    {entry}");
                }
            }
        }
    }

    manager.profile
           .save_file(cli.profile)
}

