use std::path::Path;

use anyhow::{Context, Result};

use crate::models::{HostResult, HostStatus, PortState, ScanResult};

pub fn write_html_file(result: &ScanResult, path: &str) -> Result<()> {
    let html = generate_html(result);
    std::fs::write(Path::new(path), &html)
        .with_context(|| format!("Failed to write HTML report to {path}"))?;
    eprintln!("[*] HTML report written to {path}");
    Ok(())
}

fn generate_html(result: &ScanResult) -> String {
    let hosts_up: Vec<&HostResult> = result
        .hosts
        .iter()
        .filter(|h| h.status == HostStatus::Up)
        .collect();

    let network_svg = generate_network_svg(&hosts_up);
    let host_cards = hosts_up
        .iter()
        .map(|h| generate_host_card(h))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nmapper Scan Report — {target}</title>
<style>
:root {{
  --bg: #0d1117;
  --card: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-dim: #8b949e;
  --accent: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #d29922;
  --purple: #bc8cff;
  --cyan: #39d2c0;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 2rem;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: var(--accent); margin-bottom: 0.5rem; font-size: 1.5rem; }}
.meta {{ color: var(--text-dim); margin-bottom: 2rem; font-size: 0.9rem; }}
.meta span {{ margin-right: 1.5rem; }}
.summary {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}}
.stat {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  text-align: center;
}}
.stat .value {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
.stat .label {{ font-size: 0.85rem; color: var(--text-dim); }}
.network-map {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 2rem;
  text-align: center;
  overflow-x: auto;
}}
.network-map h2 {{ color: var(--text); margin-bottom: 1rem; font-size: 1.1rem; }}
.host-card {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 1rem;
}}
.host-header {{
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 0.5rem;
  flex-wrap: wrap;
}}
.host-ip {{ font-size: 1.2rem; font-weight: bold; color: var(--cyan); }}
.host-hostname {{ color: var(--text-dim); }}
.host-mac {{ color: var(--text-dim); font-size: 0.85rem; }}
.host-vendor {{ color: var(--purple); font-size: 0.85rem; }}
.host-mdns {{ color: var(--yellow); font-size: 0.85rem; }}
.badge {{
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: bold;
}}
.badge-up {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.badge-os {{ background: rgba(188,140,255,0.15); color: var(--purple); }}
table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 0.75rem;
  font-size: 0.9rem;
}}
th {{
  text-align: left;
  padding: 0.5rem 0.75rem;
  border-bottom: 2px solid var(--border);
  color: var(--text-dim);
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}}
td {{
  padding: 0.4rem 0.75rem;
  border-bottom: 1px solid var(--border);
}}
tr:last-child td {{ border-bottom: none; }}
.port-open {{ color: var(--green); }}
.port-closed {{ color: var(--red); }}
.port-filtered {{ color: var(--yellow); }}
.section-title {{
  color: var(--accent);
  font-size: 0.95rem;
  font-weight: bold;
  margin-top: 1rem;
  margin-bottom: 0.5rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.25rem;
}}
.subsection {{ color: var(--cyan); font-weight: bold; margin-top: 0.5rem; font-size: 0.85rem; }}
.dns-list {{ list-style: none; padding-left: 1rem; font-size: 0.85rem; color: var(--text); }}
.dns-list li {{ padding: 0.1rem 0; }}
.http-200 {{ color: var(--green); }}
.http-3xx {{ color: var(--yellow); }}
.http-err {{ color: var(--red); }}
.footer {{
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 0.85rem;
  text-align: center;
}}
</style>
</head>
<body>
<div class="container">
<h1>nmapper Scan Report</h1>
<div class="meta">
  <span>Target: {target}</span>
  <span>Scan type: {scan_type}</span>
  <span>Duration: {duration:.2}s</span>
  <span>Date: {date}</span>
</div>

<div class="summary">
  <div class="stat"><div class="value">{hosts_scanned}</div><div class="label">Hosts Scanned</div></div>
  <div class="stat"><div class="value" style="color:var(--green)">{hosts_up}</div><div class="label">Hosts Up</div></div>
  <div class="stat"><div class="value" style="color:var(--red)">{hosts_down}</div><div class="label">Hosts Down</div></div>
  <div class="stat"><div class="value">{ports_scanned}</div><div class="label">Ports Scanned</div></div>
</div>

<div class="network-map">
<h2>Network Map</h2>
{network_svg}
</div>

{host_cards}

<div class="footer">
  Generated by nmapper v{version}
</div>
</div>
</body>
</html>"#,
        target = html_escape(&result.scan_info.target_spec),
        scan_type = html_escape(&result.scan_info.scan_type),
        duration = result.scan_info.duration_secs,
        date = html_escape(&result.scan_info.start_time),
        hosts_scanned = result.scan_info.total_hosts_scanned,
        hosts_up = result.scan_info.hosts_up,
        hosts_down = result.scan_info.total_hosts_scanned - result.scan_info.hosts_up,
        ports_scanned = result.scan_info.total_ports_scanned,
        network_svg = network_svg,
        host_cards = host_cards,
        version = env!("CARGO_PKG_VERSION"),
    )
}

fn generate_host_card(host: &HostResult) -> String {
    let hostname = host
        .hostname
        .as_ref()
        .map(|h| format!(r#"<span class="host-hostname">({})</span>"#, html_escape(h)))
        .unwrap_or_default();

    let mac_line = host
        .mac_address
        .as_ref()
        .map(|mac| {
            let vendor = host
                .vendor
                .as_ref()
                .map(|v| format!(r#" <span class="host-vendor">{}</span>"#, html_escape(v)))
                .unwrap_or_default();
            format!(
                r#"<div class="host-mac">MAC: {}{}</div>"#,
                html_escape(&mac.to_string()),
                vendor
            )
        })
        .unwrap_or_default();

    let mdns_line = host
        .mdns_names
        .as_ref()
        .filter(|n| !n.is_empty())
        .map(|names| {
            format!(
                r#"<div class="host-mdns">mDNS: {}</div>"#,
                html_escape(&names.join(", "))
            )
        })
        .unwrap_or_default();

    let os_badge = host
        .os
        .as_ref()
        .map(|os| {
            format!(
                r#"<span class="badge badge-os">{} ({:.0}%)</span>"#,
                html_escape(&os.name),
                os.confidence * 100.0
            )
        })
        .unwrap_or_default();

    let open_ports: Vec<_> = host
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .collect();

    let port_table = if open_ports.is_empty() {
        r#"<p style="color:var(--text-dim);margin-top:0.5rem">No open ports found.</p>"#
            .to_string()
    } else {
        let rows: Vec<String> = open_ports
            .iter()
            .map(|p| {
                let state_class = match p.state {
                    PortState::Open => "port-open",
                    PortState::Closed => "port-closed",
                    PortState::Filtered => "port-filtered",
                };
                let svc_name = p
                    .service
                    .as_ref()
                    .map(|s| html_escape(&s.name))
                    .unwrap_or_else(|| "-".to_string());
                let svc_ver = p
                    .service
                    .as_ref()
                    .and_then(|s| s.version.as_ref())
                    .map(|v| html_escape(v))
                    .unwrap_or_else(|| "-".to_string());
                format!(
                    r#"<tr><td>{}/{}</td><td class="{}">{}</td><td>{}</td><td>{}</td></tr>"#,
                    p.port, p.protocol, state_class, p.state, svc_name, svc_ver
                )
            })
            .collect();

        format!(
            r#"<table>
<thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
<tbody>{}</tbody>
</table>"#,
            rows.join("\n")
        )
    };

    let closed = host.ports.iter().filter(|p| p.state == PortState::Closed).count();
    let filtered = host.ports.iter().filter(|p| p.state == PortState::Filtered).count();
    let not_shown = if closed > 0 || filtered > 0 {
        let mut parts = Vec::new();
        if closed > 0 {
            parts.push(format!("{closed} closed"));
        }
        if filtered > 0 {
            parts.push(format!("{filtered} filtered"));
        }
        format!(
            r#"<p style="color:var(--text-dim);font-size:0.85rem;margin-top:0.25rem">Not shown: {}</p>"#,
            parts.join(", ")
        )
    } else {
        String::new()
    };

    // Traceroute section
    let traceroute_section = if host.traceroute.is_empty() {
        String::new()
    } else {
        let rows: Vec<String> = host
            .traceroute
            .iter()
            .map(|hop| {
                let ip_str = hop
                    .ip
                    .map(|ip| html_escape(&ip.to_string()))
                    .unwrap_or_else(|| "*".to_string());
                let hostname_str = hop
                    .hostname
                    .as_deref()
                    .map(|h| html_escape(h))
                    .unwrap_or_default();
                let rtt_str = hop
                    .rtt_ms
                    .map(|r| format!("{r:.1}ms"))
                    .unwrap_or_else(|| "*".to_string());
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    hop.ttl, ip_str, hostname_str, rtt_str
                )
            })
            .collect();
        format!(
            r#"<div class="section-title">Traceroute</div>
<table>
<thead><tr><th>TTL</th><th>IP</th><th>Hostname</th><th>RTT</th></tr></thead>
<tbody>{}</tbody>
</table>"#,
            rows.join("\n")
        )
    };

    // DNS Enumeration section
    let dns_section = if let Some(ref dns) = host.dns_enum {
        let mut parts = Vec::new();
        parts.push(r#"<div class="section-title">DNS Enumeration</div>"#.to_string());

        if !dns.zone_transfer.is_empty() {
            parts.push(format!(
                r#"<div class="subsection">Zone Transfer: {} record{}</div><ul class="dns-list">{}</ul>"#,
                dns.zone_transfer.len(),
                if dns.zone_transfer.len() == 1 { "" } else { "s" },
                dns.zone_transfer
                    .iter()
                    .map(|r| format!("<li>{}</li>", html_escape(r)))
                    .collect::<Vec<_>>()
                    .join("")
            ));
        }

        if !dns.subdomains.is_empty() {
            parts.push(format!(
                r#"<div class="subsection">Subdomains: {} found</div><ul class="dns-list">{}</ul>"#,
                dns.subdomains.len(),
                dns.subdomains
                    .iter()
                    .map(|r| format!(
                        "<li>{} {} {}</li>",
                        html_escape(&r.name),
                        html_escape(&r.record_type),
                        html_escape(&r.value)
                    ))
                    .collect::<Vec<_>>()
                    .join("")
            ));
        }

        if !dns.reverse_dns.is_empty() {
            parts.push(format!(
                r#"<div class="subsection">Reverse DNS: {} record{}</div><ul class="dns-list">{}</ul>"#,
                dns.reverse_dns.len(),
                if dns.reverse_dns.len() == 1 { "" } else { "s" },
                dns.reverse_dns
                    .iter()
                    .map(|r| format!(
                        "<li>{} {} {}</li>",
                        html_escape(&r.name),
                        html_escape(&r.record_type),
                        html_escape(&r.value)
                    ))
                    .collect::<Vec<_>>()
                    .join("")
            ));
        }

        parts.join("\n")
    } else {
        String::new()
    };

    // HTTP Paths section
    let http_section = if host.http_paths.is_empty() {
        String::new()
    } else {
        let mut parts = Vec::new();
        for hp in &host.http_paths {
            let rows: Vec<String> = hp
                .paths
                .iter()
                .map(|p| {
                    let status_class = match p.status {
                        200..=299 => "http-200",
                        300..=399 => "http-3xx",
                        _ => "http-err",
                    };
                    let detail = if let Some(ref redirect) = p.redirect {
                        format!("&rarr; {}", html_escape(redirect))
                    } else if let Some(len) = p.content_length {
                        format!("{}B", len)
                    } else {
                        String::new()
                    };
                    format!(
                        r#"<tr><td class="{}">{}</td><td>{}</td><td>{}</td></tr>"#,
                        status_class, p.status, html_escape(&p.path), detail
                    )
                })
                .collect();
            parts.push(format!(
                r#"<div class="section-title">HTTP Paths (port {})</div>
<table>
<thead><tr><th>Status</th><th>Path</th><th>Detail</th></tr></thead>
<tbody>{}</tbody>
</table>"#,
                hp.port,
                rows.join("\n")
            ));
        }
        parts.join("\n")
    };

    format!(
        r#"<div class="host-card">
<div class="host-header">
  <span class="host-ip">{ip}</span>
  {hostname}
  <span class="badge badge-up">up</span>
  {os_badge}
</div>
{mac_line}
{mdns_line}
{port_table}
{not_shown}
{traceroute_section}
{dns_section}
{http_section}
</div>"#,
        ip = host.ip,
        hostname = hostname,
        os_badge = os_badge,
        mac_line = mac_line,
        mdns_line = mdns_line,
        port_table = port_table,
        not_shown = not_shown,
        traceroute_section = traceroute_section,
        dns_section = dns_section,
        http_section = http_section,
    )
}

fn generate_network_svg(hosts: &[&HostResult]) -> String {
    if hosts.is_empty() {
        return r#"<p style="color:var(--text-dim)">No hosts to display.</p>"#.to_string();
    }

    let has_traceroute = hosts.iter().any(|h| !h.traceroute.is_empty());

    if has_traceroute {
        generate_layered_svg(hosts)
    } else {
        generate_radial_svg(hosts)
    }
}

fn generate_layered_svg(hosts: &[&HostResult]) -> String {
    use std::collections::{HashMap, HashSet};

    // Collect unique intermediate routers from all traceroute hops
    // (exclude the final hop which is the target itself)
    let mut routers: Vec<String> = Vec::new();
    let mut router_set: HashSet<String> = HashSet::new();
    // Map: target_ip -> list of router IPs in the path
    let mut target_routes: HashMap<String, Vec<String>> = HashMap::new();

    for host in hosts {
        let mut path_routers = Vec::new();
        let hop_count = host.traceroute.len();
        for (i, hop) in host.traceroute.iter().enumerate() {
            // Skip the last hop (the target itself) and hops with no IP
            if i + 1 < hop_count {
                if let Some(ip) = hop.ip {
                    let ip_str = ip.to_string();
                    if router_set.insert(ip_str.clone()) {
                        routers.push(ip_str.clone());
                    }
                    path_routers.push(ip_str);
                }
            }
        }
        target_routes.insert(host.ip.to_string(), path_routers);
    }

    let router_count = routers.len();
    let host_count = hosts.len();
    let max_nodes = std::cmp::max(router_count, host_count).max(1);

    let node_spacing = 120.0_f64;
    let svg_width = ((max_nodes as f64) * node_spacing + 160.0) as u32;
    let svg_height = 380_u32;

    let layer1_y = 50.0; // Scanner
    let layer2_y = 180.0; // Routers
    let layer3_y = 310.0; // Targets

    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {svg_width} {svg_height}\" style=\"max-width:{svg_width}px;width:100%\">"
    ));

    let center_x = svg_width as f64 / 2.0;

    // Layer 1: Scanner node
    svg.push_str(&format!(
        "<circle cx=\"{center_x}\" cy=\"{layer1_y}\" r=\"25\" fill=\"#1f6feb\" stroke=\"#58a6ff\" stroke-width=\"2\"/>\
         <text x=\"{center_x}\" y=\"{}\" text-anchor=\"middle\" fill=\"white\" font-size=\"9\" font-weight=\"bold\">Scanner</text>",
        layer1_y + 4.0
    ));

    // Layer 2: Router nodes
    let mut router_positions: HashMap<String, f64> = HashMap::new();
    if !routers.is_empty() {
        let total_width = (router_count as f64 - 1.0) * node_spacing;
        let start_x = center_x - total_width / 2.0;
        for (i, router_ip) in routers.iter().enumerate() {
            let rx = start_x + i as f64 * node_spacing;
            router_positions.insert(router_ip.clone(), rx);

            // Line from scanner to router
            svg.push_str(&format!(
                "<line x1=\"{center_x}\" y1=\"{}\" x2=\"{rx}\" y2=\"{}\" stroke=\"#30363d\" stroke-width=\"1\" stroke-dasharray=\"4,2\"/>",
                layer1_y + 25.0,
                layer2_y - 14.0
            ));

            svg.push_str(&format!(
                "<circle cx=\"{rx}\" cy=\"{layer2_y}\" r=\"14\" fill=\"#d29922\" stroke=\"#e3b341\" stroke-width=\"2\"/>\
                 <text x=\"{rx}\" y=\"{}\" text-anchor=\"middle\" fill=\"white\" font-size=\"7\" font-weight=\"bold\">R</text>",
                layer2_y + 3.0
            ));

            // Router IP label below
            let short_ip = router_ip.rsplit('.').next().unwrap_or(router_ip);
            svg.push_str(&format!(
                "<text x=\"{rx}\" y=\"{}\" text-anchor=\"middle\" fill=\"#8b949e\" font-size=\"7\">.{}</text>",
                layer2_y + 26.0,
                html_escape(short_ip)
            ));
        }
    }

    // Layer 3: Target host nodes
    let total_width = (host_count as f64 - 1.0) * node_spacing;
    let start_x = center_x - total_width / 2.0;
    for (i, host) in hosts.iter().enumerate() {
        let hx = start_x + i as f64 * node_spacing;
        let ip_str = host.ip.to_string();

        let open_ports = host
            .ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .count();

        let (fill, stroke_c) = host_node_colors(host, open_ports);
        let node_r = if open_ports > 10 {
            22.0
        } else if open_ports > 3 {
            18.0
        } else {
            14.0
        };

        // Draw lines from routers to this target
        if let Some(route) = target_routes.get(&ip_str) {
            if let Some(last_router) = route.last() {
                if let Some(&rx) = router_positions.get(last_router) {
                    svg.push_str(&format!(
                        "<line x1=\"{rx}\" y1=\"{}\" x2=\"{hx}\" y2=\"{}\" stroke=\"#30363d\" stroke-width=\"1\"/>",
                        layer2_y + 14.0,
                        layer3_y - node_r
                    ));
                }
            } else {
                // No routers in path — direct line from scanner
                svg.push_str(&format!(
                    "<line x1=\"{center_x}\" y1=\"{}\" x2=\"{hx}\" y2=\"{}\" stroke=\"#30363d\" stroke-width=\"1\"/>",
                    layer1_y + 25.0,
                    layer3_y - node_r
                ));
            }
        } else {
            // No traceroute data for this host — direct from scanner
            svg.push_str(&format!(
                "<line x1=\"{center_x}\" y1=\"{}\" x2=\"{hx}\" y2=\"{}\" stroke=\"#30363d\" stroke-width=\"1\"/>",
                layer1_y + 25.0,
                layer3_y - node_r
            ));
        }

        svg.push_str(&format!(
            "<circle cx=\"{hx}\" cy=\"{layer3_y}\" r=\"{node_r}\" fill=\"{fill}\" stroke=\"{stroke_c}\" stroke-width=\"2\"/>"
        ));

        let short_ip = ip_str.rsplit('.').next().unwrap_or(&ip_str);
        svg.push_str(&format!(
            "<text x=\"{hx}\" y=\"{}\" text-anchor=\"middle\" fill=\"white\" font-size=\"8\" font-weight=\"bold\">.{short_ip}</text>",
            layer3_y + 3.0
        ));

        let label = host
            .vendor
            .as_deref()
            .or(host.hostname.as_deref())
            .unwrap_or("");
        if !label.is_empty() {
            let short_label = if label.len() > 16 {
                &label[..16]
            } else {
                label
            };
            svg.push_str(&format!(
                "<text x=\"{hx}\" y=\"{}\" text-anchor=\"middle\" fill=\"#8b949e\" font-size=\"7\">{}</text>",
                layer3_y + node_r + 12.0,
                html_escape(short_label),
            ));
        }

        if open_ports > 0 {
            let port_y = layer3_y + node_r + if label.is_empty() { 12.0 } else { 22.0 };
            let suffix = if open_ports == 1 { "" } else { "s" };
            svg.push_str(&format!(
                "<text x=\"{hx}\" y=\"{port_y}\" text-anchor=\"middle\" fill=\"#3fb950\" font-size=\"7\">{open_ports} port{suffix}</text>"
            ));
        }
    }

    svg.push_str("</svg>");
    svg
}

fn host_node_colors(host: &HostResult, open_ports: usize) -> (&'static str, &'static str) {
    if let Some(ref os) = host.os {
        match os.name.as_str() {
            n if n.contains("Linux") => ("#2ea043", "#3fb950"),
            n if n.contains("Windows") => ("#1f6feb", "#58a6ff"),
            n if n.contains("macOS") || n.contains("iOS") => ("#8b949e", "#c9d1d9"),
            n if n.contains("IoT") || n.contains("Network") => ("#d29922", "#e3b341"),
            _ => ("#6e7681", "#8b949e"),
        }
    } else if open_ports > 5 {
        ("#bc8cff", "#d2a8ff")
    } else {
        ("#39d2c0", "#56d4c8")
    }
}

fn generate_radial_svg(hosts: &[&HostResult]) -> String {
    let count = hosts.len();
    let radius = if count <= 4 {
        120.0
    } else if count <= 10 {
        180.0
    } else {
        240.0
    };
    let cx = radius + 80.0;
    let cy = radius + 80.0;
    let width = (cx + radius + 80.0) as u32;
    let height = (cy + radius + 80.0) as u32;

    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {width} {height}\" style=\"max-width:{width}px;width:100%\">"
    ));

    let text_y = cy + 4.0;
    svg.push_str(&format!(
        "<circle cx=\"{cx}\" cy=\"{cy}\" r=\"30\" fill=\"#1f6feb\" stroke=\"#58a6ff\" stroke-width=\"2\"/>\
         <text x=\"{cx}\" y=\"{text_y}\" text-anchor=\"middle\" fill=\"white\" font-size=\"10\" font-weight=\"bold\">Network</text>"
    ));

    for (i, host) in hosts.iter().enumerate() {
        let angle = (2.0 * std::f64::consts::PI * i as f64) / count as f64
            - std::f64::consts::FRAC_PI_2;
        let hx = cx + radius * angle.cos();
        let hy = cy + radius * angle.sin();

        let open_ports = host
            .ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .count();

        let (fill, stroke_c) = host_node_colors(host, open_ports);

        let node_r = if open_ports > 10 {
            22.0
        } else if open_ports > 3 {
            18.0
        } else {
            14.0
        };

        svg.push_str(&format!(
            "<line x1=\"{cx}\" y1=\"{cy}\" x2=\"{hx}\" y2=\"{hy}\" stroke=\"#30363d\" stroke-width=\"1\"/>"
        ));

        svg.push_str(&format!(
            "<circle cx=\"{hx}\" cy=\"{hy}\" r=\"{node_r}\" fill=\"{fill}\" stroke=\"{stroke_c}\" stroke-width=\"2\"/>"
        ));

        let ip_str = host.ip.to_string();
        let short_ip = ip_str.rsplit('.').next().unwrap_or(&ip_str);
        let label_y = hy + 3.0;
        svg.push_str(&format!(
            "<text x=\"{hx}\" y=\"{label_y}\" text-anchor=\"middle\" fill=\"white\" font-size=\"8\" font-weight=\"bold\">.{short_ip}</text>"
        ));

        let label = host
            .vendor
            .as_deref()
            .or(host.hostname.as_deref())
            .unwrap_or("");
        if !label.is_empty() {
            let short_label = if label.len() > 16 {
                &label[..16]
            } else {
                label
            };
            let name_y = hy + node_r + 12.0;
            svg.push_str(&format!(
                "<text x=\"{hx}\" y=\"{name_y}\" text-anchor=\"middle\" fill=\"#8b949e\" font-size=\"7\">{}</text>",
                html_escape(short_label),
            ));
        }

        if open_ports > 0 {
            let port_y = hy + node_r + if label.is_empty() { 12.0 } else { 22.0 };
            let suffix = if open_ports == 1 { "" } else { "s" };
            svg.push_str(&format!(
                "<text x=\"{hx}\" y=\"{port_y}\" text-anchor=\"middle\" fill=\"#3fb950\" font-size=\"7\">{open_ports} port{suffix}</text>"
            ));
        }
    }

    svg.push_str("</svg>");
    svg
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
