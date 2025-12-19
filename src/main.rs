mod cli;
mod dns;
mod pcap;
mod ui;

use std::process::exit;

use anyhow::Result;
use clap::Parser;
use cli::Args;
use dns::{DnsCollector, DnsState};
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_interfaces {
        let interfaces = pcap::CaptureLoader::list_interfaces()?;
        println!("Available network interfaces:");
        for device in interfaces {
            let status = if device.flags.is_up() { "UP" } else { "DOWN" };
            let running = if device.flags.is_running() {
                "RUNNING"
            } else {
                ""
            };
            let loopback = if device.flags.is_loopback() {
                "LOOPBACK"
            } else {
                ""
            };

            println!("  {} [{}] {} {}", device.name, status, running, loopback);

            if let Some(desc) = device.desc {
                println!("    Description: {desc}");
            }
        }
        return Ok(());
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    let interface = if let Some(ref iface) = args.interface {
        iface.clone()
    } else {
        pcap::CaptureLoader::select_default_interface()?
    };

    info!("Starting DNS Query Monitor");
    info!("Interface: {interface}");

    info!("Starting packet capture...");
    let (_capture_handle, event_rx, cancel_token) = pcap::CaptureLoader::load(&interface)?;
    info!("Packet capture started successfully");

    let collector = DnsCollector::new(event_rx);
    let dns_state = DnsState::new(collector.aggregator());

    let collector_handle = tokio::spawn(async move {
        if let Err(e) = collector.run().await {
            eprintln!("Collector error: {e}");
        }
    });

    let app = ui::App::new(dns_state);
    ui::run_ui(app).await?;

    info!("DNS Query Monitor stopped");

    // Cancel packet capture first
    info!("Cancelling packet capture...");
    cancel_token.cancel();

    // Drop the collector to close the channel
    drop(collector_handle);

    // Don't wait for the capture handle - let it finish in background
    // This is a workaround for pcap blocking issues on some systems
    info!("DNS Query Monitor stopped");
    exit(0)
}
