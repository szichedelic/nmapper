mod cli;
mod models;
mod network;
mod output;
mod scanner;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use anyhow::{bail, Result};
use clap::Parser;
use colored::Colorize;
use rand::seq::SliceRandom;

use cli::Cli;
use models::*;
use network::{is_root, parse_ports, parse_targets, reverse_dns};
use output::{diff, html, json, table};
use scanner::{
    host_discovery, mac_vendor, mdns, os_fingerprint, port_scanner, service_detect, ssdp,
    tls_inspect, vuln_check,
};
use port_scanner::RawScanOpts;

async fn run_scan(
    targets: &[IpAddr],
    ports: &[u16],
    scan_type: ScanType,
    discovery: DiscoveryMethod,
    timing: &TimingConfig,
    raw_opts: &RawScanOpts,
    cli: &Cli,
) -> Result<ScanResult> {
    let start_time = Instant::now();

    eprintln!(
        "{}",
        format!("[*] Host discovery ({discovery:?})...").dimmed()
    );
    let discovery_results =
        host_discovery::discover_hosts(targets, discovery, timing, cli.verbose).await;

    let mut live_hosts: Vec<IpAddr> = discovery_results
        .iter()
        .filter(|r| r.status == HostStatus::Up)
        .map(|r| r.ip)
        .collect();

    // Randomize host scan order for stealth
    live_hosts.shuffle(&mut rand::thread_rng());

    eprintln!(
        "{}",
        format!(
            "[*] Discovery complete: {}/{} hosts up",
            live_hosts.len(),
            targets.len()
        )
        .dimmed()
    );

    let mdns_map: HashMap<IpAddr, Vec<String>> = if cli.mdns {
        eprintln!("{}", "[*] mDNS/Bonjour discovery (3s)...".dimmed());
        let results = tokio::task::spawn_blocking(move || mdns::mdns_discover(3, false))
            .await
            .unwrap_or_default();
        let count = results.len();
        let map: HashMap<_, _> = results.into_iter().map(|r| (r.ip, r.names)).collect();
        eprintln!(
            "{}",
            format!("[*] mDNS: found {} device(s) with names", count).dimmed()
        );
        map
    } else {
        HashMap::new()
    };

    let ssdp_map: HashMap<IpAddr, Vec<String>> = if cli.ssdp {
        eprintln!("{}", "[*] SSDP/UPnP discovery (3s)...".dimmed());
        let results = tokio::task::spawn_blocking(move || ssdp::ssdp_discover(3, false))
            .await
            .unwrap_or_default();
        let count = results.len();
        let map: HashMap<_, _> = results
            .into_iter()
            .map(|d| {
                let mut info = Vec::new();
                if let Some(name) = d.friendly_name {
                    info.push(name);
                }
                if let Some(server) = d.server {
                    info.push(server);
                } else if let Some(dtype) = d.device_type {
                    info.push(dtype);
                }
                (d.ip, info)
            })
            .filter(|(_, info)| !info.is_empty())
            .collect();
        eprintln!(
            "{}",
            format!("[*] SSDP: found {} device(s)", count).dimmed()
        );
        map
    } else {
        HashMap::new()
    };

    let mut host_results = Vec::new();
    let mut port_count = 0;

    // Interleave mode: scan one port across all hosts, then next port
    // This distributes probes across targets, making per-host detection harder
    let interleaved_port_results: HashMap<IpAddr, Vec<PortResult>> = if cli.interleave && live_hosts.len() > 1 {
        eprintln!(
            "{}",
            "[*] Interleave mode: distributing probes across hosts".dimmed()
        );
        let mut results_map: HashMap<IpAddr, Vec<PortResult>> = HashMap::new();
        for &ip in &live_hosts {
            results_map.insert(ip, Vec::new());
        }

        let mut shuffled_ports: Vec<u16> = ports.to_vec();
        shuffled_ports.shuffle(&mut rand::thread_rng());

        for &port in &shuffled_ports {
            let port_slice = &[port];
            for &ip in &live_hosts {
                let mut result =
                    port_scanner::scan_ports(ip, port_slice, scan_type, timing, raw_opts, cli.verbose).await;
                if let Some(entry) = results_map.get_mut(&ip) {
                    entry.append(&mut result);
                }
            }
        }

        // Sort each host's results by port number
        for results in results_map.values_mut() {
            results.sort_by_key(|r| r.port);
        }
        port_count = results_map.values().map(|v| v.len()).sum();
        results_map
    } else {
        HashMap::new()
    };

    for &ip in &live_hosts {
        eprintln!();
        eprintln!("{}", format!("[*] Scanning {ip}...").dimmed());

        let hostname = reverse_dns(ip);
        if let Some(ref name) = hostname {
            if cli.verbose {
                eprintln!("  [*] Hostname: {name}");
            }
        }

        let discovery_info = discovery_results.iter().find(|r| r.ip == ip);
        let mac_address = discovery_info.and_then(|r| r.mac_address);
        let vendor = mac_address
            .as_ref()
            .and_then(|mac| mac_vendor::lookup_vendor(mac).map(String::from));
        if cli.verbose {
            if let Some(ref mac) = mac_address {
                let v = vendor.as_deref().unwrap_or("Unknown");
                eprintln!("  [*] MAC: {mac} ({v})");
            }
        }

        let mut port_results = if cli.interleave && live_hosts.len() > 1 {
            interleaved_port_results.get(&ip).cloned().unwrap_or_default()
        } else {
            eprintln!(
                "{}",
                format!("  [*] Port scanning ({} ports)...", ports.len()).dimmed()
            );
            let results =
                port_scanner::scan_ports(ip, ports, scan_type, timing, raw_opts, cli.verbose).await;
            port_count += results.len();
            results
        };

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
            service_detect::detect_services(ip, &mut port_results, timing, cli.verbose).await;

            let tls_ports: Vec<u16> = port_results
                .iter()
                .filter(|p| {
                    p.state == PortState::Open
                        && matches!(p.port, 443 | 8443 | 4443 | 993 | 995 | 636 | 989 | 990)
                })
                .map(|p| p.port)
                .collect();
            for tls_port in tls_ports {
                if cli.verbose {
                    eprintln!("  [*] TLS inspection on port {tls_port}...");
                }
                let tls_info = tls_inspect::inspect_tls(ip, tls_port, cli.verbose);
                if let Some(info) = tls_info {
                    if let Some(port_result) =
                        port_results.iter_mut().find(|p| p.port == tls_port)
                    {
                        if let Some(ref mut svc) = port_result.service {
                            svc.tls_info = Some(info);
                        }
                    }
                }
            }
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

        let traceroute_hops = if cli.traceroute {
            eprintln!("{}", "  [*] Traceroute...".dimmed());
            scanner::traceroute::traceroute(ip, cli.verbose)
        } else {
            Vec::new()
        };

        let warnings = if cli.vuln_check {
            eprintln!("{}", "  [*] Vulnerability checks...".dimmed());
            vuln_check::check_vulnerabilities(ip, &port_results, cli.verbose)
        } else {
            Vec::new()
        };

        let dns_enum = if cli.dns_enum {
            let has_dns = port_results.iter().any(|p| p.port == 53 && p.state == PortState::Open);
            if has_dns {
                eprintln!("{}", "  [*] DNS enumeration...".dimmed());
                let domain = hostname.as_deref();
                let subnet = cli.targets.split('/').next().and_then(|ip_str| {
                    let parts: Vec<&str> = ip_str.split('.').collect();
                    if parts.len() == 4 {
                        Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
                    } else {
                        None
                    }
                });
                Some(scanner::dns_enum::dns_enumerate(
                    ip,
                    domain,
                    subnet.as_deref(),
                    cli.verbose,
                ))
            } else {
                None
            }
        } else {
            None
        };

        let mdns_names = mdns_map.get(&ip).cloned();
        let ssdp_info = ssdp_map.get(&ip).cloned();
        host_results.push(HostResult {
            ip,
            hostname,
            mac_address,
            vendor,
            mdns_names,
            ssdp_info,
            status: HostStatus::Up,
            ports: port_results,
            os,
            traceroute: traceroute_hops,
            dns_enum,
            warnings,
        });
    }

    for result in &discovery_results {
        if result.status != HostStatus::Up {
            host_results.push(HostResult {
                ip: result.ip,
                hostname: None,
                mac_address: result.mac_address,
                vendor: result.mac_address.as_ref().and_then(|mac| {
                    mac_vendor::lookup_vendor(mac).map(String::from)
                }),
                mdns_names: None,
                ssdp_info: None,
                status: result.status,
                ports: Vec::new(),
                os: None,
                traceroute: Vec::new(),
                dns_enum: None,
                warnings: Vec::new(),
            });
        }
    }

    let total_ports_scanned = port_count;
    let duration = start_time.elapsed().as_secs_f64();

    Ok(ScanResult {
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
    })
}

fn output_results(
    scan_result: &ScanResult,
    output_format: OutputFormat,
    cli: &Cli,
) -> Result<()> {
    match output_format {
        OutputFormat::Table => table::print_table(scan_result),
        OutputFormat::Json => json::print_json(scan_result)?,
        OutputFormat::Html => {
            let path = cli.output_file.as_deref().unwrap_or("nmapper-report.html");
            html::write_html_file(scan_result, path)?;
        }
        OutputFormat::Both => {
            table::print_table(scan_result);
            json::print_json(scan_result)?;
        }
    }

    if output_format != OutputFormat::Html {
        if let Some(ref path) = cli.output_file {
            if path.ends_with(".html") || path.ends_with(".htm") {
                html::write_html_file(scan_result, path)?;
            } else {
                json::write_json_file(scan_result, path)?;
            }
        }
    }

    if cli.diff {
        diff::diff_scan(scan_result)?;
    }

    Ok(())
}

/// Compare two scan results and print alerts about changes.
fn print_watch_diff(prev: &ScanResult, curr: &ScanResult, iteration: u64) {
    eprintln!();
    eprintln!(
        "{}",
        format!("=== Watch iteration #{iteration} — comparing against previous scan ===")
            .bold()
            .cyan()
    );

    let prev_hosts: HashMap<IpAddr, &HostResult> = prev
        .hosts
        .iter()
        .filter(|h| h.status == HostStatus::Up)
        .map(|h| (h.ip, h))
        .collect();

    let curr_hosts: HashMap<IpAddr, &HostResult> = curr
        .hosts
        .iter()
        .filter(|h| h.status == HostStatus::Up)
        .map(|h| (h.ip, h))
        .collect();

    let mut changes = 0;

    for (&ip, host) in &curr_hosts {
        if !prev_hosts.contains_key(&ip) {
            let label = host.hostname.as_deref().unwrap_or("");
            eprintln!(
                "  {} {} {ip} {label}",
                "NEW HOST".on_green().black().bold(),
                "+".green()
            );
            changes += 1;
        }
    }

    for (&ip, host) in &prev_hosts {
        if !curr_hosts.contains_key(&ip) {
            let label = host.hostname.as_deref().unwrap_or("");
            eprintln!(
                "  {} {} {ip} {label}",
                "HOST GONE".on_red().white().bold(),
                "-".red()
            );
            changes += 1;
        }
    }

    for (&ip, curr_host) in &curr_hosts {
        if let Some(prev_host) = prev_hosts.get(&ip) {
            let prev_open: HashMap<u16, &PortResult> = prev_host
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .map(|p| (p.port, p))
                .collect();

            let curr_open: HashMap<u16, &PortResult> = curr_host
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .map(|p| (p.port, p))
                .collect();

            for (&port, pr) in &curr_open {
                if !prev_open.contains_key(&port) {
                    let svc = pr
                        .service
                        .as_ref()
                        .map(|s| s.name.as_str())
                        .unwrap_or("unknown");
                    eprintln!(
                        "  {} {ip}:{port} ({svc})",
                        "PORT OPENED".yellow().bold()
                    );
                    changes += 1;
                }
            }

            for (&port, pr) in &prev_open {
                if !curr_open.contains_key(&port) {
                    let svc = pr
                        .service
                        .as_ref()
                        .map(|s| s.name.as_str())
                        .unwrap_or("unknown");
                    eprintln!(
                        "  {} {ip}:{port} ({svc})",
                        "PORT CLOSED".red().bold()
                    );
                    changes += 1;
                }
            }
        }
    }

    if changes == 0 {
        eprintln!(
            "  {}",
            "No changes detected since last scan.".dimmed()
        );
    } else {
        eprintln!(
            "  {}",
            format!("{changes} change(s) detected!").yellow().bold()
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let scan_type = match cli.scan_type.to_lowercase().as_str() {
        "syn" => ScanType::Syn,
        "connect" => ScanType::Connect,
        "udp" => ScanType::Udp,
        "fin" => ScanType::Fin,
        "null" => ScanType::Null,
        "xmas" => ScanType::Xmas,
        other => bail!("Unknown scan type: {other}. Use: syn, connect, udp, fin, null, xmas"),
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
        "html" => OutputFormat::Html,
        "both" => OutputFormat::Both,
        other => bail!("Unknown output format: {other}. Use: table, json, html, both"),
    };

    let mut timing = TimingConfig::from_template(cli.timing.min(5));
    if let Some(max_par) = cli.max_parallel {
        timing.max_parallel = max_par;
    }
    if let Some(timeout) = cli.timeout {
        timing.timeout_ms = timeout;
    }

    let decoy_ips: Vec<std::net::Ipv4Addr> = cli
        .decoys
        .iter()
        .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .collect();

    if !cli.decoys.is_empty() && decoy_ips.len() != cli.decoys.len() {
        eprintln!(
            "{}",
            "WARNING: Some decoy IPs could not be parsed and were skipped."
                .yellow()
        );
    }

    let raw_opts = RawScanOpts {
        randomize_tcp: cli.randomize_tcp,
        decoys: decoy_ips,
        fragment: cli.fragment,
    };

    let needs_root = scan_type.is_raw()
        || matches!(discovery, DiscoveryMethod::Arp)
        || cli.os_detect
        || cli.traceroute;

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

    if cli.passive {
        if !is_root() {
            eprintln!(
                "{}",
                "Passive mode requires root privileges for packet capture."
                    .yellow()
                    .bold()
            );
            eprintln!("{}", "Run with: sudo nmapper --passive".yellow());
            return Ok(());
        }
        eprintln!(
            "{}",
            format!(
                "nmapper v{} — passive discovery mode",
                env!("CARGO_PKG_VERSION")
            )
            .bold()
        );
        scanner::passive::passive_discover(cli.duration, cli.verbose);
        return Ok(());
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

    if cli.watch {
        eprintln!(
            "{}",
            format!(
                "Watch mode: scanning every {}s (Ctrl+C to stop)",
                cli.interval
            )
            .cyan()
            .bold()
        );
    }

    eprintln!(
        "Targets: {} ({} host(s)) | Ports: {} | Timing: T{} ({})",
        cli.targets,
        targets.len(),
        cli.ports,
        cli.timing,
        timing.label
    );
    eprintln!();

    if cli.watch {
        let mut prev_result: Option<ScanResult> = None;
        let mut iteration: u64 = 0;

        loop {
            iteration += 1;

            if iteration > 1 {
                eprintln!();
                eprintln!(
                    "{}",
                    format!(
                        "=== Watch: starting scan #{iteration} at {} ===",
                        chrono::Local::now().format("%H:%M:%S")
                    )
                    .bold()
                    .cyan()
                );
            }

            let scan_result =
                run_scan(&targets, &ports, scan_type, discovery, &timing, &raw_opts, &cli).await?;

            if let Some(ref prev) = prev_result {
                print_watch_diff(prev, &scan_result, iteration);
            }

            output_results(&scan_result, output_format, &cli)?;

            prev_result = Some(scan_result);

            eprintln!();
            eprintln!(
                "{}",
                format!(
                    "[*] Next scan in {}s... (Ctrl+C to stop)",
                    cli.interval
                )
                .dimmed()
            );
            tokio::time::sleep(std::time::Duration::from_secs(cli.interval)).await;
        }
    } else {
        let scan_result =
            run_scan(&targets, &ports, scan_type, discovery, &timing, &raw_opts, &cli).await?;

        output_results(&scan_result, output_format, &cli)?;
    }

    Ok(())
}
