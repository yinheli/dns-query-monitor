use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "dns-query-monitor")]
#[command(about = "Real-time DNS query monitoring with TUI", long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub interface: Option<String>,

    #[arg(short, long)]
    pub filter: Option<String>,

    #[arg(short, long, default_value = "info")]
    pub log_level: String,

    #[arg(long)]
    pub list_interfaces: bool,
}
