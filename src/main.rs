mod cli;
mod models;
mod network;
mod output;
mod scanner;

use std::time::Instant;

use anyhow::{bail, Result};
use clap::Parser;
use colored::Colorize;

use cli::Cli;
use models::*;
use network::{is_root, parse_ports, parse_targets, reverse_dns};
use output::{json, table};
use scanner::{host_discovery, os_fingerprint, port_scanner, service_detect};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let start_time = Instant::now();

    let scan_type = match cli.scan_type.to_lowercase().as_str() {
        "syn" => ScanType::Syn,
        "connect" => ScanType::Connect,
        "udp" => ScanType::Udp,
        other => bail!("Unknown scan type: {other}. Use: syn, connect, udp"),
    };

    let discovery = match cli.discovery.to_lowercase().as_str() {
        "arp" => DiscoveryMethod::Arp,
        "icmp" => DiscoveryMethod::Icmp,
        "tcp" => DiscoveryMethod::Tcp,
        "skip" => DiscoveryMethod::Skip,
        other => bail!("Unknown discovery method: {other}. Use: arp, icmp, tcp, skip"),
    };

    let output_format = match cli.output.to_lowercase().as_str() {
        "table" => OutputFormat::Table,
        "json" => OutputFormat::Json,
        "both" => OutputFormat::Both,
        other => bail!("Unknown output format: {other}. Use: table, json, both"),
    };

    let mut timing = TimingConfig::from_template(cli.timing.min(5));
    if let Some(max_par) = cli.max_parallel {
        timing.max_parallel = max_par;
    }
    if let Some(timeout) = cli.timeout {
        timing.timeout_ms = timeout;
    }

    let needs_root = matches!(scan_type, ScanType::Syn)
        || matches!(discovery, DiscoveryMethod::Arp)
        || cli.os_detect;

    if needs_root && !is_root() {
        eprintln!(
            "{}",
            "WARNING: This scan type requires root privileges."
                .yellow()
                .bold()
        );
        eprintln!("{}", "Run with: sudo nmapper ...".yellow());
        eprintln!(
            "{}",
            "Falling back to unprivileged modes where possible.\n".yellow()
        );
    }

    let targets = parse_targets(&cli.targets)?;
    let ports = parse_ports(&cli.ports)?;

    eprintln!(
        "{}",
        format!(
            "nmapper v{} — starting {} scan",
            env!("CARGO_PKG_VERSION"),
            scan_type
        )
        .bold()
    );
    eprintln!(
        "Targets: {} ({} host(s)) | Ports: {} | Timing: T{} ({})",
        cli.targets,
        targets.len(),
        cli.ports,
        cli.timing,
        timing.label
    );
    eprintln!();

    eprintln!(
        "{}",
        format!("[*] Host discovery ({discovery:?})...").dimmed()
    );
    let discovery_results =
        host_discovery::discover_hosts(&targets, discovery, &timing, cli.verbose).await;

    let live_hosts: Vec<std::net::IpAddr> = discovery_results
        .iter()
        .filter(|r| r.status == HostStatus::Up)
        .map(|r| r.ip)
        .collect();

    eprintln!(
        "{}",
        format!(
            "[*] Discovery complete: {}/{} hosts up",
            live_hosts.len(),
            targets.len()
        )
        .dimmed()
    );

    if live_hosts.is_empty() {
        eprintln!("{}", "No live hosts found. Exiting.".yellow());
        return Ok(());
    }

    let mut host_results = Vec::new();

    let mut port_count = 0;

    for &ip in &live_hosts {
        eprintln!();
        eprintln!("{}", format!("[*] Scanning {ip}...").dimmed());

        let hostname = reverse_dns(ip);
        if let Some(ref name) = hostname {
            if cli.verbose {
                eprintln!("  [*] Hostname: {name}");
            }
        }

        eprintln!(
            "{}",
            format!("  [*] Port scanning ({} ports)...", ports.len()).dimmed()
        );
        let mut port_results =
            port_scanner::scan_ports(ip, &ports, scan_type, &timing, cli.verbose).await;
        port_count += port_results.len();

        let open_count = port_results
            .iter()
            .filter(|p| p.state == PortState::Open)
            .count();
        eprintln!(
            "{}",
            format!("  [*] Found {open_count} open port(s)").dimmed()
        );

        if cli.service_version && open_count > 0 {
            eprintln!("{}", "  [*] Service/version detection...".dimmed());
            service_detect::detect_services(ip, &mut port_results, &timing, cli.verbose).await;
        }

        let os = if cli.os_detect {
            if let Some(open_port) = port_results.iter().find(|p| p.state == PortState::Open) {
                eprintln!("{}", "  [*] OS fingerprinting...".dimmed());
                os_fingerprint::fingerprint_os(ip, open_port.port, cli.verbose)
            } else {
                if cli.verbose {
                    eprintln!("  [!] No open ports for OS fingerprinting");
                }
                None
            }
        } else {
            None
        };

        host_results.push(HostResult {
            ip,
            hostname,
            status: HostStatus::Up,
            ports: port_results,
            os,
        });
    }

    for result in &discovery_results {
        if result.status != HostStatus::Up {
            host_results.push(HostResult {
                ip: result.ip,
                hostname: None,
                status: result.status,
                ports: Vec::new(),
                os: None,
            });
        }
    }

    let total_ports_scanned = port_count;
    let duration = start_time.elapsed().as_secs_f64();

    let scan_result = ScanResult {
        hosts: host_results,
        scan_info: ScanInfo {
            start_time: chrono::Local::now().to_rfc3339(),
            duration_secs: duration,
            target_spec: cli.targets.clone(),
            scan_type: scan_type.to_string(),
            total_hosts_scanned: targets.len(),
            hosts_up: live_hosts.len(),
            total_ports_scanned,
        },
    };

    match output_format {
        OutputFormat::Table => table::print_table(&scan_result),
        OutputFormat::Json => json::print_json(&scan_result)?,
        OutputFormat::Both => {
            table::print_table(&scan_result);
            json::print_json(&scan_result)?;
        }
    }

    if let Some(ref path) = cli.output_file {
        json::write_json_file(&scan_result, path)?;
    }

    Ok(())
}
