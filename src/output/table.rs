use colored::Colorize;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

use crate::models::{HostResult, HostStatus, PortState, ScanResult};

/// Print scan results as a formatted CLI table.
pub fn print_table(result: &ScanResult) {
    println!();
    println!(
        "{}",
        format!(
            "nmapper scan report — {} host(s) scanned in {:.2}s",
            result.scan_info.total_hosts_scanned, result.scan_info.duration_secs
        )
        .bold()
    );
    println!(
        "Target: {} | Scan type: {}",
        result.scan_info.target_spec, result.scan_info.scan_type
    );
    println!("{}", "─".repeat(70));

    let hosts_up: Vec<&HostResult> = result
        .hosts
        .iter()
        .filter(|h| h.status == HostStatus::Up)
        .collect();

    if hosts_up.is_empty() {
        println!("{}", "No hosts found up.".yellow());
        return;
    }

    for host in &hosts_up {
        print_host(host);
    }

    println!("{}", "─".repeat(70));
    println!(
        "{}",
        format!(
            "Summary: {} host(s) up, {} host(s) down, {} total ports scanned",
            result.scan_info.hosts_up,
            result.scan_info.total_hosts_scanned - result.scan_info.hosts_up,
            result.scan_info.total_ports_scanned,
        )
        .bold()
    );
    println!();
}

fn print_host(host: &HostResult) {
    println!();

    let hostname_str = host
        .hostname
        .as_ref()
        .map(|h| format!(" ({h})"))
        .unwrap_or_default();

    println!(
        "{} {}{}",
        "HOST:".bold(),
        host.ip.to_string().cyan().bold(),
        hostname_str.dimmed()
    );
    if let Some(ref mac) = host.mac_address {
        let vendor_str = host
            .vendor
            .as_ref()
            .map(|v| format!(" ({v})"))
            .unwrap_or_default();
        println!("MAC: {}{}", mac.to_string().cyan(), vendor_str.dimmed());
    }
    println!(
        "Status: {}",
        match host.status {
            HostStatus::Up => "up".green().bold(),
            HostStatus::Down => "down".red().bold(),
            HostStatus::Unknown => "unknown".yellow(),
        }
    );

    if let Some(ref names) = host.mdns_names {
        if !names.is_empty() {
            println!("mDNS: {}", names.join(", ").yellow());
        }
    }

    if let Some(ref ssdp) = host.ssdp_info {
        if !ssdp.is_empty() {
            println!("SSDP: {}", ssdp.join(", ").yellow());
        }
    }

    if let Some(ref os) = host.os {
        println!(
            "OS: {} (confidence: {:.0}%)",
            os.name.magenta().bold(),
            os.confidence * 100.0
        );
        println!(
            "   TTL={}, Window={}, DF={}, TCP Options={}",
            os.details.ttl, os.details.window_size, os.details.df_bit, os.details.tcp_options_order
        );
    }

    let open_ports: Vec<_> = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .collect();

    if open_ports.is_empty() {
        println!("  {}", "No open ports found.".dimmed());
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("PORT")
                .set_alignment(CellAlignment::Right)
                .add_attribute(Attribute::Bold),
            Cell::new("STATE").add_attribute(Attribute::Bold),
            Cell::new("SERVICE").add_attribute(Attribute::Bold),
            Cell::new("VERSION").add_attribute(Attribute::Bold),
        ]);

    for port in &open_ports {
        let port_str = format!("{}/{}", port.port, port.protocol);
        let state_cell = match port.state {
            PortState::Open => Cell::new("open").fg(Color::Green),
            PortState::Closed => Cell::new("closed").fg(Color::Red),
            PortState::Filtered => Cell::new("filtered").fg(Color::Yellow),
        };
        let service_name = port
            .service
            .as_ref()
            .map(|s| s.name.as_str())
            .unwrap_or("-");
        let version = port
            .service
            .as_ref()
            .and_then(|s| s.version.as_deref())
            .unwrap_or("-");

        table.add_row(vec![
            Cell::new(&port_str).set_alignment(CellAlignment::Right),
            state_cell,
            Cell::new(service_name),
            Cell::new(version),
        ]);
    }

    println!("{table}");

    for port in &open_ports {
        if let Some(ref svc) = port.service {
            if let Some(ref tls) = svc.tls_info {
                println!(
                    "  {} TLS on port {}: {}",
                    "TLS:".magenta().bold(),
                    port.port,
                    tls.subject.cyan()
                );
                println!("      Issuer: {}", tls.issuer.dimmed());
                println!(
                    "      Valid: {} to {}",
                    tls.not_before, tls.not_after
                );
                if !tls.sans.is_empty() {
                    println!("      SANs: {}", tls.sans.join(", ").dimmed());
                }
            }
        }
    }

    if !host.traceroute.is_empty() {
        println!();
        println!("  Traceroute:");
        for hop in &host.traceroute {
            let ip_str = hop
                .ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "*".to_string());
            let name = hop.hostname.as_deref().unwrap_or("");
            let rtt = hop
                .rtt_ms
                .map(|r| format!("{r:.1}ms"))
                .unwrap_or_else(|| "*".to_string());
            println!("    {:>2}  {:<16} {:<30} {}", hop.ttl, ip_str, name, rtt);
        }
    }

    let closed_count = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Closed)
        .count();
    let filtered_count = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Filtered)
        .count();

    if !host.warnings.is_empty() {
        println!();
        for warning in &host.warnings {
            let severity_colored = match warning.severity.as_str() {
                "critical" => warning.severity.to_uppercase().red().bold(),
                "high" => warning.severity.to_uppercase().red(),
                "medium" => warning.severity.to_uppercase().yellow(),
                _ => warning.severity.to_uppercase().dimmed(),
            };
            println!(
                "  [!] {} (port {}): {}",
                severity_colored, warning.port, warning.description
            );
        }
    }

    if closed_count > 0 || filtered_count > 0 {
        let mut parts = Vec::new();
        if closed_count > 0 {
            parts.push(format!("{closed_count} closed"));
        }
        if filtered_count > 0 {
            parts.push(format!("{filtered_count} filtered"));
        }
        println!("  Not shown: {}", parts.join(", ").dimmed());
    }
}
