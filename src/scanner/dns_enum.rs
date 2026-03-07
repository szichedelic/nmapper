use crate::models::{DnsEnumResult, DnsRecord};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, UdpSocket};
use std::time::Duration;

const DNS_TIMEOUT_MS: u64 = 3000;

// DNS record type constants
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;
const TYPE_AXFR: u16 = 252;

/// Main entry point for DNS enumeration.
pub fn dns_enumerate(
    dns_server: IpAddr,
    domain: Option<&str>,
    subnet_prefix: Option<&str>,
    verbose: bool,
) -> DnsEnumResult {
    let zone_transfer = if let Some(dom) = domain {
        attempt_zone_transfer(dns_server, dom, verbose)
    } else {
        Vec::new()
    };

    let subdomains = if let Some(dom) = domain {
        subdomain_brute(dns_server, dom, verbose)
    } else {
        Vec::new()
    };

    let reverse_dns = if let Some(prefix) = subnet_prefix {
        reverse_dns_sweep(dns_server, prefix, verbose)
    } else {
        Vec::new()
    };

    if verbose {
        eprintln!(
            "    DNS enum: {} zone records, {} subdomains, {} reverse entries",
            zone_transfer.len(),
            subdomains.len(),
            reverse_dns.len()
        );
    }

    DnsEnumResult {
        zone_transfer,
        subdomains,
        reverse_dns,
    }
}

/// Build a raw DNS query packet.
fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let id = rand::random::<u16>();
    let mut buf = Vec::with_capacity(64);

    // Header: ID, flags (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section: encode name as labels
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label

    buf.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS = IN

    buf
}

/// Parse a DNS name from a buffer, handling compression pointers.
/// Returns (name, bytes_consumed_from_offset).
fn parse_dns_name(buf: &[u8], offset: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut bytes_consumed = 0;

    loop {
        if pos >= buf.len() {
            break;
        }

        let len = buf[pos] as usize;

        if len == 0 {
            if !jumped {
                bytes_consumed = pos - offset + 1;
            }
            break;
        }

        // Compression pointer: top 2 bits set
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                break;
            }
            if !jumped {
                bytes_consumed = pos - offset + 2;
            }
            let pointer = ((len & 0x3F) << 8) | (buf[pos + 1] as usize);
            pos = pointer;
            jumped = true;
            continue;
        }

        pos += 1;
        if pos + len > buf.len() {
            break;
        }
        if let Ok(label) = std::str::from_utf8(&buf[pos..pos + len]) {
            labels.push(label.to_string());
        }
        pos += len;
    }

    if !jumped && bytes_consumed == 0 {
        bytes_consumed = pos - offset;
    }

    (labels.join("."), bytes_consumed)
}

/// Send a UDP DNS query and return the response buffer.
fn dns_query(server: IpAddr, query: &[u8]) -> Option<Vec<u8>> {
    let addr = format!("{server}:53");
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(DNS_TIMEOUT_MS)))
        .ok()?;
    socket.send_to(query, &addr).ok()?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Parse DNS response answer section, extracting A, AAAA, CNAME, and PTR records.
fn parse_dns_response(buf: &[u8]) -> Vec<DnsRecord> {
    let mut records = Vec::new();

    if buf.len() < 12 {
        return records;
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    // Skip header
    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        let (_, consumed) = parse_dns_name(buf, pos);
        pos += consumed;
        pos += 4; // QTYPE + QCLASS
        if pos > buf.len() {
            return records;
        }
    }

    // Parse answer section
    for _ in 0..ancount {
        if pos >= buf.len() {
            break;
        }

        let (name, consumed) = parse_dns_name(buf, pos);
        pos += consumed;

        if pos + 10 > buf.len() {
            break;
        }

        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        // skip class (2) and TTL (4)
        pos += 8;
        let rdlength = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;

        if pos + rdlength > buf.len() {
            break;
        }

        match rtype {
            TYPE_A if rdlength == 4 => {
                let ip = format!(
                    "{}.{}.{}.{}",
                    buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]
                );
                records.push(DnsRecord {
                    name: name.clone(),
                    record_type: "A".to_string(),
                    value: ip,
                });
            }
            TYPE_AAAA if rdlength == 16 => {
                let mut parts = Vec::new();
                for i in 0..8 {
                    let word =
                        u16::from_be_bytes([buf[pos + i * 2], buf[pos + i * 2 + 1]]);
                    parts.push(format!("{word:04x}"));
                }
                records.push(DnsRecord {
                    name: name.clone(),
                    record_type: "AAAA".to_string(),
                    value: parts.join(":"),
                });
            }
            TYPE_CNAME | TYPE_PTR => {
                let (target, _) = parse_dns_name(buf, pos);
                let rtype_str = if rtype == TYPE_CNAME { "CNAME" } else { "PTR" };
                records.push(DnsRecord {
                    name: name.clone(),
                    record_type: rtype_str.to_string(),
                    value: target,
                });
            }
            _ => {}
        }

        pos += rdlength;
    }

    records
}

/// Attempt an AXFR (zone transfer) via TCP.
fn attempt_zone_transfer(server: IpAddr, domain: &str, verbose: bool) -> Vec<String> {
    if verbose {
        eprintln!("    Attempting zone transfer for {domain}...");
    }

    let query = build_dns_query(domain, TYPE_AXFR);
    let addr = format!("{server}:53");

    let mut stream = match TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_millis(DNS_TIMEOUT_MS),
    ) {
        Ok(s) => s,
        Err(_) => {
            if verbose {
                eprintln!("    Zone transfer: TCP connect failed");
            }
            return Vec::new();
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_millis(DNS_TIMEOUT_MS)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(DNS_TIMEOUT_MS)));

    // TCP DNS: 2-byte length prefix
    let len = query.len() as u16;
    if stream.write_all(&len.to_be_bytes()).is_err() {
        return Vec::new();
    }
    if stream.write_all(&query).is_err() {
        return Vec::new();
    }

    // Read response
    let mut len_buf = [0u8; 2];
    if stream.read_exact(&mut len_buf).is_err() {
        if verbose {
            eprintln!("    Zone transfer: no response (transfer refused or not supported)");
        }
        return Vec::new();
    }

    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 65535 {
        return Vec::new();
    }

    let mut resp_buf = vec![0u8; resp_len];
    if stream.read_exact(&mut resp_buf).is_err() {
        return Vec::new();
    }

    // Check RCODE - if non-zero, transfer was refused
    if resp_buf.len() >= 4 {
        let rcode = resp_buf[3] & 0x0F;
        if rcode != 0 {
            if verbose {
                eprintln!("    Zone transfer refused (RCODE={rcode})");
            }
            return Vec::new();
        }
    }

    let records = parse_dns_response(&resp_buf);
    let result: Vec<String> = records
        .into_iter()
        .map(|r| format!("{} {} {}", r.name, r.record_type, r.value))
        .collect();

    if verbose {
        eprintln!("    Zone transfer: {} record(s)", result.len());
    }

    result
}

/// Reverse DNS sweep: PTR queries for .1 through .254 in a /24 subnet.
fn reverse_dns_sweep(server: IpAddr, prefix: &str, verbose: bool) -> Vec<DnsRecord> {
    if verbose {
        eprintln!("    Reverse DNS sweep for {prefix}.1-254...");
    }

    let mut records = Vec::new();

    for i in 1..=254u8 {
        let parts: Vec<&str> = prefix.split('.').collect();
        if parts.len() != 3 {
            break;
        }
        let ptr_name = format!("{i}.{}.{}.{}.in-addr.arpa", parts[2], parts[1], parts[0]);
        let query = build_dns_query(&ptr_name, TYPE_PTR);

        if let Some(resp) = dns_query(server, &query) {
            let parsed = parse_dns_response(&resp);
            for rec in parsed {
                if rec.record_type == "PTR" {
                    records.push(DnsRecord {
                        name: format!("{prefix}.{i}"),
                        record_type: "PTR".to_string(),
                        value: rec.value,
                    });
                }
            }
        }
    }

    if verbose {
        eprintln!("    Reverse DNS: {} PTR record(s) found", records.len());
    }

    records
}

/// Brute-force common subdomains via A record queries.
fn subdomain_brute(server: IpAddr, domain: &str, verbose: bool) -> Vec<DnsRecord> {
    if verbose {
        eprintln!("    Subdomain brute-force for {domain}...");
    }

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
        let query = build_dns_query(&fqdn, TYPE_A);

        if let Some(resp) = dns_query(server, &query) {
            // Check RCODE is NOERROR (0) and ANCOUNT > 0
            if resp.len() >= 8 {
                let rcode = resp[3] & 0x0F;
                let ancount = u16::from_be_bytes([resp[6], resp[7]]);
                if rcode == 0 && ancount > 0 {
                    let parsed = parse_dns_response(&resp);
                    for rec in parsed {
                        records.push(DnsRecord {
                            name: fqdn.clone(),
                            record_type: rec.record_type,
                            value: rec.value,
                        });
                    }
                }
            }
        }
    }

    if verbose {
        eprintln!("    Subdomain brute: {} record(s) found", records.len());
    }

    records
}
