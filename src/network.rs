use anyhow::{bail, Context, Result};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, ToSocketAddrs};

/// Parse a target specification into a list of IP addresses.
/// Supports: single IP, hostname, CIDR notation.
pub fn parse_targets(target: &str) -> Result<Vec<IpAddr>> {
    if target.contains('/') {
        let network: IpNetwork = target
            .parse()
            .with_context(|| format!("Invalid CIDR notation: {target}"))?;
        let ips: Vec<IpAddr> = network.iter().collect();
        if ips.is_empty() {
            bail!("CIDR range {target} contains no addresses");
        }
        return Ok(ips);
    }

    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let addrs: Vec<IpAddr> = format!("{target}:0")
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve hostname: {target}"))?
        .map(|sa| sa.ip())
        .collect();

    if addrs.is_empty() {
        bail!("Could not resolve hostname: {target}");
    }

    Ok(vec![addrs[0]])
}

/// Parse a port specification string into a sorted, deduplicated list of ports.
/// Supports: "22", "22,80,443", "1-1024", "22,80,100-200", "common"
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    if spec == "common" {
        return Ok(common_ports());
    }

    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                bail!("Invalid port range: {part}");
            }
            let start: u16 = range[0]
                .parse()
                .with_context(|| format!("Invalid port number: {}", range[0]))?;
            let end: u16 = range[1]
                .parse()
                .with_context(|| format!("Invalid port number: {}", range[1]))?;
            if start > end {
                bail!("Invalid port range: {start}-{end} (start > end)");
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let port: u16 = part
                .parse()
                .with_context(|| format!("Invalid port number: {part}"))?;
            ports.push(port);
        }
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Top 100 most common ports (based on nmap's frequency data).
fn common_ports() -> Vec<u16> {
    vec![
        7, 20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143,
        161, 162, 179, 194, 389, 443, 445, 465, 500, 514, 515, 520, 521, 548, 554, 587, 631, 636,
        873, 902, 989, 990, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1701, 1723, 1812, 1813,
        2049, 2082, 2083, 2086, 2087, 2096, 2181, 2222, 3268, 3306, 3389, 3690, 4443, 4444, 4567,
        4711, 4993, 5000, 5001, 5060, 5432, 5631, 5632, 5900, 5901, 5984, 5985, 5986, 6000, 6379,
        6667, 7001, 7002, 8000, 8008, 8080, 8081, 8443, 8834, 8888, 9090, 9100, 9200, 9418, 9999,
        10000, 27017, 27018,
    ]
}

/// Resolve an IP address to a hostname via reverse DNS.
pub fn reverse_dns(ip: IpAddr) -> Option<String> {
    dns_lookup::lookup_addr(&ip).ok()
}

/// Check if the current process has root/admin privileges.
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
