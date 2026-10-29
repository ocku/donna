mod anchors;
pub mod cli;
mod client;
mod config;
mod constants;
mod listeners;
mod net;
mod output;
mod server;

use anyhow::Result;
use clap::CommandFactory;
use cli::{Cli, Command};
use std::io::Write;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Query(args) => client::run_query(args).await?,
        Command::Resolve(args) => client::run_resolve(args).await?,
        Command::Serve => {
            server::serve(
                cli.config
                    .as_deref()
                    .unwrap_or(constants::default_config_path()),
            )
            .await?
        }
        Command::Check => {
            let path = cli
                .config
                .as_deref()
                .unwrap_or(constants::default_config_path());
            let (config, base) = config::Config::load(path)?;
            server::prepare(&config, &base).await?;
            writeln!(
                std::io::stdout().lock(),
                "{}: configuration is valid ({} listeners, {} zones)",
                path.display(),
                config.listen.len(),
                config.zones.len()
            )?;
        }
        Command::CheckZone { origin, file } => {
            let apex = dns::DomainName::from_dotted(&origin)?;
            let master = dns::master::MasterFile::from_path(&file, Some(apex.clone()))?;
            let count = master.records.len();
            nameserver::Zone::from_master(apex, master)?;
            writeln!(
                std::io::stdout().lock(),
                "{}: {origin} is valid ({count} records)",
                file.display()
            )?;
        }
        Command::Config { role } => std::io::stdout()
            .lock()
            .write_all(config::example(role).as_bytes())?,
        Command::Completions { shell } => {
            let mut completion = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "donna", &mut completion);
            std::io::stdout().lock().write_all(&completion)?;
        }
    }
    Ok(())
}
