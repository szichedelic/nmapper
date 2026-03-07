# v0.3.0 Network Intelligence — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add traceroute, DNS enumeration, HTTP path discovery, and an interactive network topology graph to make nmapper a full network intelligence tool.

**Architecture:** Four new scanner modules (`traceroute`, `dns_enum`, `http_enum`) plus a major upgrade to `output/html.rs` for topology rendering. Each module follows the existing pattern: standalone function called from `main.rs`, results stored in new model structs on `HostResult`. The topology graph uses the traceroute hop data to draw a layered network diagram in SVG, embedded in the existing HTML report.

**Tech Stack:** `pnet` for raw ICMP traceroute, `std::net::UdpSocket` for DNS wire protocol, `tokio` for async HTTP requests, inline SVG generation for topology.

---

## Task 1: Traceroute Module

**Files:**
- Create: `src/scanner/traceroute.rs`
- Modify: `src/scanner/mod.rs` (add `pub mod traceroute;`)
- Modify: `src/models.rs` (add `TracerouteHop` struct and `traceroute` field on `HostResult`)
- Modify: `src/cli.rs` (add `--traceroute` flag)
- Modify: `src/main.rs` (call traceroute after port scan, store results)

### Step 1: Add models

Add to `src/models.rs` after the `OsDetails` struct (line 143):

```rust
#[derive(Debug, Clone, Serialize)]
pub struct TracerouteHop {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
}
```

Add field to `HostResult` struct after `os`:

```rust
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub traceroute: Vec<TracerouteHop>,
```

Update both `HostResult` construction sites in `src/main.rs` (the live host push and the down host push) to include `traceroute: Vec::new()` initially.

### Step 2: Add CLI flag

Add to `src/cli.rs` after the `--interleave` flag:

```rust
    /// Perform traceroute to each host
    #[arg(long = "traceroute")]
    pub traceroute: bool,
```

### Step 3: Create traceroute module

Create `src/scanner/traceroute.rs`:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use std::mem::MaybeUninit;

use socket2::{Domain, Protocol, Socket, Type};

use crate::models::TracerouteHop;

const MAX_HOPS: u8 = 30;
const TIMEOUT_MS: u64 = 1000;
const DST_PORT: u16 = 33434;

/// Perform ICMP-based traceroute to target. Returns list of hops.
pub fn traceroute(target: IpAddr, verbose: bool) -> Vec<TracerouteHop> {
    match target {
        IpAddr::V4(v4) => traceroute_v4(v4, verbose),
        IpAddr::V6(_) => {
            if verbose {
                eprintln!("  [!] Traceroute not yet supported for IPv6");
            }
            Vec::new()
        }
    }
}

fn traceroute_v4(target: Ipv4Addr, verbose: bool) -> Vec<TracerouteHop> {
    // We send UDP packets with increasing TTL.
    // When TTL expires, intermediate routers send ICMP Time Exceeded.
    // When we reach the target, it sends ICMP Port Unreachable.
    let send_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let recv_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .ok();

    let mut hops = Vec::new();

    for ttl in 1..=MAX_HOPS {
        send_socket
            .set_ttl(ttl as u32)
            .ok();

        let dest = SocketAddr::new(IpAddr::V4(target), DST_PORT + ttl as u16);
        let start = Instant::now();

        // Send a small UDP packet
        if send_socket.send_to(&[0u8; 32], dest).is_err() {
            hops.push(TracerouteHop {
                ttl,
                ip: None,
                hostname: None,
                rtt_ms: None,
            });
            continue;
        }

        // Listen for ICMP response
        let mut buf: [MaybeUninit<u8>; 512] = unsafe { MaybeUninit::uninit().assume_init() };

        match recv_socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                let hop_ip = match addr.as_socket_ipv4() {
                    Some(v4) => IpAddr::V4(*v4.ip()),
                    None => continue,
                };

                let hostname = dns_lookup::lookup_addr(&hop_ip).ok();

                if verbose {
                    let name = hostname.as_deref().unwrap_or("");
                    eprintln!("  [*] TTL {ttl:>2}: {hop_ip} ({name}) {rtt:.1}ms");
                }

                let reached_target = hop_ip == IpAddr::V4(target);

                hops.push(TracerouteHop {
                    ttl,
                    ip: Some(hop_ip),
                    hostname,
                    rtt_ms: Some(rtt),
                });

                // Check if we got ICMP Port Unreachable (type 3) = reached target
                // or if the source IP matches the target
                if reached_target {
                    break;
                }

                // Also check ICMP type in the raw packet
                // IP header is at least 20 bytes, ICMP type is first byte after
                if n >= 28 {
                    let ip_hdr_len = unsafe { (buf[0].assume_init() & 0x0F) as usize * 4 };
                    if n > ip_hdr_len {
                        let icmp_type = unsafe { buf[ip_hdr_len].assume_init() };
                        // Type 3 = Destination Unreachable (we reached the target)
                        if icmp_type == 3 {
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                // Timeout — no response for this hop
                if verbose {
                    eprintln!("  [*] TTL {ttl:>2}: * (timeout)");
                }
                hops.push(TracerouteHop {
                    ttl,
                    ip: None,
                    hostname: None,
                    rtt_ms: None,
                });
            }
        }
    }

    hops
}
```

### Step 4: Register module

Add to `src/scanner/mod.rs`:

```rust
pub mod traceroute;
```

### Step 5: Wire into main.rs

In `src/main.rs`, add traceroute call inside the `for &ip in &live_hosts` loop, after the OS fingerprinting block and before the vuln_check block:

```rust
        let traceroute_hops = if cli.traceroute {
            eprintln!("{}", "  [*] Traceroute...".dimmed());
            scanner::traceroute::traceroute(ip, cli.verbose)
        } else {
            Vec::new()
        };
```

Update the `HostResult` construction for live hosts to include:

```rust
            traceroute: traceroute_hops,
```

Update the `HostResult` construction for down hosts to include:

```rust
            traceroute: Vec::new(),
```

### Step 6: Add traceroute to table output

In `src/output/table.rs`, after the port table output for each host, add traceroute display:

```rust
    // Show traceroute if available
    if !host.traceroute.is_empty() {
        println!("\n  Traceroute:");
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
```

### Step 7: Update root check

In `src/main.rs`, update `needs_root` to include traceroute:

```rust
    let needs_root = scan_type.is_raw()
        || matches!(discovery, DiscoveryMethod::Arp)
        || cli.os_detect
        || cli.traceroute;
```

### Step 8: Commit

```bash
git add src/scanner/traceroute.rs src/scanner/mod.rs src/models.rs src/cli.rs src/main.rs src/output/table.rs
git commit -m "feat(scanner): add traceroute with TTL-based hop discovery"
```

---

## Task 2: DNS Enumeration Module

**Files:**
- Create: `src/scanner/dns_enum.rs`
- Modify: `src/scanner/mod.rs` (add `pub mod dns_enum;`)
- Modify: `src/models.rs` (add `DnsEnumResult` struct and field on `HostResult`)
- Modify: `src/cli.rs` (add `--dns-enum` flag)
- Modify: `src/main.rs` (call dns_enum for hosts with port 53 open)

### Step 1: Add models

Add to `src/models.rs` after `TracerouteHop`:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct DnsEnumResult {
    pub zone_transfer: Vec<String>,
    pub subdomains: Vec<DnsRecord>,
    pub reverse_dns: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
}
```

Add field to `HostResult` after `traceroute`:

```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_enum: Option<DnsEnumResult>,
```

Update both `HostResult` construction sites in `src/main.rs` to include `dns_enum: None`.

### Step 2: Add CLI flag

Add to `src/cli.rs`:

```rust
    /// DNS enumeration (zone transfer, reverse DNS sweep)
    #[arg(long = "dns-enum")]
    pub dns_enum: bool,
```

### Step 3: Create DNS enumeration module

Create `src/scanner/dns_enum.rs`:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::models::{DnsEnumResult, DnsRecord};

const DNS_TIMEOUT_MS: u64 = 3000;

/// Perform DNS enumeration against a DNS server.
/// Attempts zone transfer (AXFR via TCP) and reverse DNS sweep.
pub fn dns_enumerate(
    dns_server: IpAddr,
    domain: Option<&str>,
    subnet_prefix: Option<&str>,
    verbose: bool,
) -> DnsEnumResult {
    let zone_transfer = if let Some(domain) = domain {
        if verbose {
            eprintln!("  [*] Attempting zone transfer for {domain}...");
        }
        attempt_zone_transfer(dns_server, domain, verbose)
    } else {
        Vec::new()
    };

    let reverse_dns = if let Some(prefix) = subnet_prefix {
        if verbose {
            eprintln!("  [*] Reverse DNS sweep on {prefix}...");
        }
        reverse_dns_sweep(dns_server, prefix, verbose)
    } else {
        Vec::new()
    };

    let subdomains = if let Some(domain) = domain {
        if verbose {
            eprintln!("  [*] Subdomain enumeration for {domain}...");
        }
        subdomain_brute(dns_server, domain, verbose)
    } else {
        Vec::new()
    };

    DnsEnumResult {
        zone_transfer,
        subdomains,
        reverse_dns,
    }
}

/// Build a DNS query packet for the given name and record type.
fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    let id: u16 = rand::random();

    // Header: ID, flags (RD=1), 1 question, 0 answers/auth/additional
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // Standard query, recursion desired
    buf.extend_from_slice(&[0x00, 0x01]); // 1 question
    buf.extend_from_slice(&[0x00, 0x00]); // 0 answers
    buf.extend_from_slice(&[0x00, 0x00]); // 0 authority
    buf.extend_from_slice(&[0x00, 0x00]); // 0 additional

    // Question: encode domain name as labels
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // Root label

    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

    buf
}

/// Parse a DNS name from a response buffer at the given offset.
/// Handles compressed labels (pointer bytes starting with 0xC0).
fn parse_dns_name(buf: &[u8], mut offset: usize) -> (String, usize) {
    let mut name = String::new();
    let mut jumped = false;
    let mut end_offset = offset;

    loop {
        if offset >= buf.len() {
            break;
        }
        let len = buf[offset] as usize;

        if len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }

        // Compression pointer
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= buf.len() {
                break;
            }
            let pointer = ((len & 0x3F) << 8) | buf[offset + 1] as usize;
            if !jumped {
                end_offset = offset + 2;
            }
            offset = pointer;
            jumped = true;
            continue;
        }

        offset += 1;
        if offset + len > buf.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&buf[offset..offset + len]));
        offset += len;
    }

    (name, end_offset)
}

/// Send a DNS query and receive the response.
fn dns_query(server: IpAddr, query: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(DNS_TIMEOUT_MS)))
        .ok()?;

    let addr = SocketAddr::new(server, 53);
    socket.send_to(query, addr).ok()?;

    let mut buf = [0u8; 4096];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

/// Parse A/PTR/CNAME records from a DNS response.
fn parse_dns_response(buf: &[u8]) -> Vec<DnsRecord> {
    let mut records = Vec::new();

    if buf.len() < 12 {
        return records;
    }

    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    // Skip header (12 bytes) and question section
    let mut offset = 12;

    // Skip questions
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    for _ in 0..qdcount {
        let (_, new_offset) = parse_dns_name(buf, offset);
        offset = new_offset + 4; // skip QTYPE + QCLASS
    }

    // Parse answers
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }

        let (name, new_offset) = parse_dns_name(buf, offset);
        offset = new_offset;

        if offset + 10 > buf.len() {
            break;
        }

        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            break;
        }

        let (record_type, value) = match rtype {
            1 if rdlength == 4 => {
                // A record
                let ip = format!(
                    "{}.{}.{}.{}",
                    buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]
                );
                ("A".to_string(), ip)
            }
            12 => {
                // PTR record
                let (ptr_name, _) = parse_dns_name(buf, offset);
                ("PTR".to_string(), ptr_name)
            }
            5 => {
                // CNAME record
                let (cname, _) = parse_dns_name(buf, offset);
                ("CNAME".to_string(), cname)
            }
            28 if rdlength == 16 => {
                // AAAA record
                let mut parts = Vec::new();
                for i in (0..16).step_by(2) {
                    parts.push(format!(
                        "{:x}",
                        u16::from_be_bytes([buf[offset + i], buf[offset + i + 1]])
                    ));
                }
                ("AAAA".to_string(), parts.join(":"))
            }
            _ => {
                offset += rdlength;
                continue;
            }
        };

        records.push(DnsRecord {
            name,
            record_type,
            value,
        });

        offset += rdlength;
    }

    records
}

/// Attempt DNS zone transfer (AXFR) via TCP.
fn attempt_zone_transfer(server: IpAddr, domain: &str, verbose: bool) -> Vec<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = SocketAddr::new(server, 53);
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(DNS_TIMEOUT_MS))
    {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(DNS_TIMEOUT_MS)))
        .ok();

    // Build AXFR query (qtype = 252)
    let query = build_dns_query(domain, 252);
    let len = (query.len() as u16).to_be_bytes();

    // TCP DNS: 2-byte length prefix + query
    let mut tcp_query = Vec::new();
    tcp_query.extend_from_slice(&len);
    tcp_query.extend_from_slice(&query);

    if stream.write_all(&tcp_query).is_err() {
        return Vec::new();
    }

    let mut response = vec![0u8; 65535];
    let n = match stream.read(&mut response) {
        Ok(n) if n > 2 => n,
        _ => return Vec::new(),
    };

    // Skip TCP length prefix
    let dns_response = &response[2..n];

    // Check RCODE — if non-zero, transfer was refused
    if dns_response.len() >= 4 {
        let rcode = dns_response[3] & 0x0F;
        if rcode != 0 {
            if verbose {
                let reason = match rcode {
                    5 => "REFUSED",
                    _ => "FAILED",
                };
                eprintln!("  [!] Zone transfer {reason} for {domain}");
            }
            return Vec::new();
        }
    }

    let records = parse_dns_response(dns_response);
    if verbose && !records.is_empty() {
        eprintln!(
            "  [+] Zone transfer returned {} records!",
            records.len()
        );
    }

    records
        .into_iter()
        .map(|r| format!("{} {} {}", r.name, r.record_type, r.value))
        .collect()
}

/// Reverse DNS sweep: query PTR records for IPs in a /24 subnet.
fn reverse_dns_sweep(server: IpAddr, prefix: &str, verbose: bool) -> Vec<DnsRecord> {
    let mut records = Vec::new();

    // Parse prefix like "192.168.1" and sweep .1-.254
    let parts: Vec<&str> = prefix.split('.').collect();
    if parts.len() != 3 {
        return records;
    }

    for i in 1..=254u8 {
        let ip_str = format!("{prefix}.{i}");
        // Build PTR query: reverse the IP and append .in-addr.arpa
        let ptr_name = format!("{i}.{}.{}.{}.in-addr.arpa", parts[2], parts[1], parts[0]);
        let query = build_dns_query(&ptr_name, 12); // PTR = 12

        if let Some(response) = dns_query(server, &query) {
            let parsed = parse_dns_response(&response);
            for rec in parsed {
                if rec.record_type == "PTR" {
                    if verbose {
                        eprintln!("  [+] {ip_str} -> {}", rec.value);
                    }
                    records.push(DnsRecord {
                        name: ip_str.clone(),
                        record_type: "PTR".to_string(),
                        value: rec.value,
                    });
                }
            }
        }
    }

    if verbose {
        eprintln!("  [*] Reverse DNS sweep found {} records", records.len());
    }

    records
}

/// Brute-force common subdomains via A record queries.
fn subdomain_brute(server: IpAddr, domain: &str, verbose: bool) -> Vec<DnsRecord> {
    let wordlist = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "ns", "ns1", "ns2",
        "dns", "mx", "vpn", "remote", "admin", "portal", "webmail",
        "api", "dev", "staging", "test", "app", "cdn", "static",
        "login", "sso", "auth", "git", "ci", "jenkins", "monitor",
        "grafana", "prometheus", "db", "database", "redis", "elastic",
        "search", "docs", "wiki", "blog", "shop", "store", "m",
        "mobile", "cloud", "backup", "gateway", "proxy", "lb",
    ];

    let mut records = Vec::new();

    for sub in &wordlist {
        let fqdn = format!("{sub}.{domain}");
        let query = build_dns_query(&fqdn, 1); // A record

        if let Some(response) = dns_query(server, &query) {
            let parsed = parse_dns_response(&response);
            for rec in parsed {
                if rec.record_type == "A" || rec.record_type == "CNAME" {
                    if verbose {
                        eprintln!("  [+] {fqdn} -> {} {}", rec.record_type, rec.value);
                    }
                    records.push(DnsRecord {
                        name: fqdn.clone(),
                        record_type: rec.record_type,
                        value: rec.value,
                    });
                }
            }
        }
    }

    if verbose {
        eprintln!("  [*] Subdomain enumeration found {} records", records.len());
    }

    records
}
```

### Step 4: Register module and wire into main.rs

Add to `src/scanner/mod.rs`:

```rust
pub mod dns_enum;
```

In `src/main.rs`, after the vuln_check block inside the host loop, add:

```rust
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
```

Add `dns_enum` to the `HostResult` construction.

### Step 5: Commit

```bash
git add src/scanner/dns_enum.rs src/scanner/mod.rs src/models.rs src/cli.rs src/main.rs
git commit -m "feat(scanner): add DNS enumeration with zone transfer, subdomain brute, and reverse sweep"
```

---

## Task 3: HTTP Path Discovery Module

**Files:**
- Create: `src/scanner/http_enum.rs`
- Modify: `src/scanner/mod.rs` (add `pub mod http_enum;`)
- Modify: `src/models.rs` (add `HttpPathResult` struct and field on `HostResult`)
- Modify: `src/cli.rs` (add `--http-enum` flag)
- Modify: `src/main.rs` (call http_enum for hosts with HTTP ports open)

### Step 1: Add models

Add to `src/models.rs`:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct HttpPathResult {
    pub port: u16,
    pub paths: Vec<HttpPath>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpPath {
    pub path: String,
    pub status: u16,
    pub content_length: Option<u64>,
    pub redirect: Option<String>,
}
```

Add field to `HostResult`:

```rust
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub http_paths: Vec<HttpPathResult>,
```

Update both `HostResult` construction sites to include `http_paths: Vec::new()`.

### Step 2: Add CLI flag

Add to `src/cli.rs`:

```rust
    /// HTTP path/directory discovery on web servers
    #[arg(long = "http-enum")]
    pub http_enum: bool,
```

### Step 3: Create HTTP enumeration module

Create `src/scanner/http_enum.rs`:

```rust
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::models::{HttpPath, HttpPathResult};

const TIMEOUT_MS: u64 = 3000;

const WORDLIST: &[&str] = &[
    "/", "/admin", "/login", "/api", "/api/v1", "/.git/HEAD",
    "/.env", "/wp-admin", "/wp-login.php", "/robots.txt",
    "/sitemap.xml", "/.well-known/security.txt", "/server-status",
    "/server-info", "/phpmyadmin", "/console", "/debug",
    "/actuator", "/actuator/health", "/swagger-ui.html",
    "/api-docs", "/graphql", "/.htaccess", "/backup",
    "/config", "/dashboard", "/manager", "/status",
    "/health", "/healthz", "/metrics", "/info",
    "/.git/config", "/.svn/entries", "/.DS_Store",
    "/wp-content", "/wp-includes", "/xmlrpc.php",
    "/cgi-bin/", "/test", "/dev", "/staging",
    "/old", "/new", "/temp", "/tmp",
];

/// Enumerate HTTP paths on the given port.
pub fn http_enumerate(
    target: IpAddr,
    port: u16,
    verbose: bool,
) -> HttpPathResult {
    let use_tls = matches!(port, 443 | 8443 | 4443);
    let mut paths = Vec::new();

    for &path in WORDLIST {
        match probe_path(target, port, path, use_tls) {
            Some(result) => {
                // Only report interesting status codes
                if matches!(result.status, 200 | 301 | 302 | 307 | 308 | 401 | 403 | 405 | 500) {
                    if verbose {
                        eprintln!(
                            "  [+] {target}:{port}{path} -> {} ({})",
                            result.status,
                            result.content_length.map(|l| format!("{l}B")).unwrap_or_default()
                        );
                    }
                    paths.push(result);
                }
            }
            None => continue,
        }
    }

    HttpPathResult { port, paths }
}

fn probe_path(target: IpAddr, port: u16, path: &str, _use_tls: bool) -> Option<HttpPath> {
    let addr = SocketAddr::new(target, port);
    let timeout = Duration::from_millis(TIMEOUT_MS);

    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;

    let host = if port == 80 || port == 443 {
        target.to_string()
    } else {
        format!("{target}:{port}")
    };

    let request = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nmapper/0.3.0\r\nConnection: close\r\n\r\n"
    );

    stream.write_all(request.as_bytes()).ok()?;

    let mut reader = BufReader::new(&stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok()?;

    // Parse "HTTP/1.1 200 OK"
    let parts: Vec<&str> = status_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let status: u16 = parts[1].parse().ok()?;

    let mut content_length = None;
    let mut redirect = None;

    // Read headers
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    break;
                }
                let lower = trimmed.to_lowercase();
                if lower.starts_with("content-length:") {
                    content_length = trimmed[15..].trim().parse().ok();
                } else if lower.starts_with("location:") {
                    redirect = Some(trimmed[9..].trim().to_string());
                }
            }
        }
    }

    Some(HttpPath {
        path: path.to_string(),
        status,
        content_length,
        redirect,
    })
}
```

### Step 4: Register module and wire into main.rs

Add to `src/scanner/mod.rs`:

```rust
pub mod http_enum;
```

In `src/main.rs`, after the dns_enum block, add:

```rust
        let http_paths = if cli.http_enum {
            let http_ports: Vec<u16> = port_results
                .iter()
                .filter(|p| {
                    p.state == PortState::Open
                        && matches!(p.port, 80 | 443 | 8080 | 8443 | 8000 | 8888 | 3000 | 5000)
                })
                .map(|p| p.port)
                .collect();
            let mut results = Vec::new();
            for port in http_ports {
                eprintln!(
                    "{}",
                    format!("  [*] HTTP enumeration on port {port}...").dimmed()
                );
                let result = scanner::http_enum::http_enumerate(ip, port, cli.verbose);
                if !result.paths.is_empty() {
                    results.push(result);
                }
            }
            results
        } else {
            Vec::new()
        };
```

Add `http_paths` to the `HostResult` construction.

### Step 5: Commit

```bash
git add src/scanner/http_enum.rs src/scanner/mod.rs src/models.rs src/cli.rs src/main.rs
git commit -m "feat(scanner): add HTTP path discovery with built-in wordlist"
```

---

## Task 4: Network Topology Graph Upgrade

**Files:**
- Modify: `src/output/html.rs` (major upgrade to SVG generation)
- Modify: `src/output/table.rs` (add traceroute/dns/http to table output)

### Step 1: Upgrade HTML topology

Replace `generate_network_svg` in `src/output/html.rs` with a layered topology that uses traceroute hop data. The new version:
- Groups hosts by subnet
- Shows traceroute hops as intermediate router nodes
- Draws layered graph: scanner → routers → targets
- Color-codes nodes by OS/type
- Shows open port counts on hover text
- Includes DNS and HTTP enumeration results in host cards

This is a large function — replace the existing `generate_network_svg` function entirely with a version that checks for traceroute data on hosts. If any host has traceroute data, render a layered topology. Otherwise, fall back to the existing radial layout.

Add to the host card generation: DNS enum results table and HTTP paths table when present.

### Step 2: Update table output

In `src/output/table.rs`, add display sections for:
- DNS enumeration results (zone transfer entries, subdomains found)
- HTTP path discovery results (path, status code, size)
- These go after the traceroute section added in Task 1

### Step 3: Commit

```bash
git add src/output/html.rs src/output/table.rs
git commit -m "feat(output): add layered topology graph and intelligence display"
```

---

## Task 5: Version Bump & README

**Files:**
- Modify: `Cargo.toml` (bump to 0.3.0)
- Modify: `README.md` (document new flags and features)

### Step 1: Bump version

Change `version = "0.2.0"` to `version = "0.3.0"` in `Cargo.toml`.

### Step 2: Update README

Add new flags to the options table:
- `--traceroute` — Perform traceroute to each host
- `--dns-enum` — DNS enumeration on hosts with port 53 open
- `--http-enum` — HTTP path/directory discovery on web servers

Add usage examples:
```
# Full network intelligence scan
sudo nmapper 192.168.1.0/24 --traceroute --dns-enum --http-enum --sV -o html

# Traceroute to a single host
sudo nmapper 10.0.0.1 --traceroute -p 22,80,443
```

Update the "How It Works" section to mention the new intelligence features.

### Step 3: Commit

```bash
git add Cargo.toml Cargo.lock README.md
git commit -m "chore: bump version to 0.3.0 and document network intelligence features"
```

---

## Task Order & Dependencies

```
Task 1 (Traceroute) — standalone, no deps
Task 2 (DNS Enum)   — standalone, no deps
Task 3 (HTTP Enum)  — standalone, no deps
Task 4 (Topology)   — depends on Tasks 1-3 (uses their model data)
Task 5 (Version)    — depends on all above
```

Tasks 1, 2, and 3 can be implemented in parallel. Task 4 must come after. Task 5 is last.

---

## Verification

After all tasks:

```bash
cargo build                                              # compiles clean
./target/debug/nmapper --help                            # shows new flags
sudo nmapper 192.168.1.1 --traceroute -p 22,80 -v       # traceroute works
sudo nmapper 192.168.1.1 --dns-enum -p 53 -v            # DNS enum works
nmapper 10.0.0.1 -s connect --http-enum -p 80,443 -v    # HTTP enum works
sudo nmapper 192.168.1.0/24 --traceroute --sV -o html   # HTML topology renders
```
