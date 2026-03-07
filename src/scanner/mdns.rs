use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone)]
pub struct MdnsResult {
    pub ip: IpAddr,
    pub names: Vec<String>,
}

/// Discover devices via mDNS by sending a query and collecting responses.
pub fn mdns_discover(duration_secs: u64, verbose: bool) -> Vec<MdnsResult> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [!] Failed to bind mDNS socket: {e}");
            return Vec::new();
        }
    };

    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();

    if socket
        .join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED)
        .is_err()
    {
        if verbose {
            eprintln!("  [!] Failed to join mDNS multicast group");
        }
    }

    // PTR query for _services._dns-sd._udp.local enumerates all advertised service types
    let query = build_mdns_query(b"\x09_services\x07_dns-sd\x04_udp\x05local\x00", 12);
    let dest = SocketAddr::new(IpAddr::V4(MDNS_ADDR), MDNS_PORT);
    socket.send_to(&query, dest).ok();

    let service_queries = [
        b"\x05_http\x04_tcp\x05local\x00".as_slice(),
        b"\x04_ssh\x04_tcp\x05local\x00".as_slice(),
        b"\x08_airplay\x04_tcp\x05local\x00".as_slice(),
        b"\x07_raop\x04_tcp\x05local\x00".as_slice(),
        b"\x0b_googlecast\x04_tcp\x05local\x00".as_slice(),
        b"\x0c_companion-link\x04_tcp\x05local\x00".as_slice(),
        b"\x07_ipp\x04_tcp\x05local\x00".as_slice(),
        b"\x08_printer\x04_tcp\x05local\x00".as_slice(),
        b"\x04_smb\x04_tcp\x05local\x00".as_slice(),
        b"\x04_afpovertcp\x04_tcp\x05local\x00".as_slice(),
        b"\x0e_home-sharing\x04_tcp\x05local\x00".as_slice(),
        b"\x08_homekit\x04_tcp\x05local\x00".as_slice(),
    ];

    for svc_name in &service_queries {
        let q = build_mdns_query(svc_name, 12);
        socket.send_to(&q, dest).ok();
        std::thread::sleep(Duration::from_millis(50));
    }

    let any_query = build_mdns_query(b"\x05local\x00", 255);
    socket.send_to(&any_query, dest).ok();

    let mut device_names: HashMap<IpAddr, Vec<String>> = HashMap::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(duration_secs);
    let mut buf = [0u8; 4096];

    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if n < 12 {
                    continue;
                }
                let names = parse_mdns_response(&buf[..n]);
                if !names.is_empty() {
                    let ip = src.ip();
                    if verbose {
                        for name in &names {
                            eprintln!("  [+] mDNS: {ip} → {name}");
                        }
                    }
                    device_names.entry(ip).or_default().extend(names);
                }
            }
            Err(_) => continue,
        }
    }

    socket
        .leave_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED)
        .ok();

    device_names
        .into_iter()
        .map(|(ip, mut names)| {
            names.sort();
            names.dedup();
            MdnsResult { ip, names }
        })
        .collect()
}

fn build_mdns_query(name_bytes: &[u8], qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(12 + name_bytes.len() + 4);

    // mDNS uses ID=0 and multicast flag cleared; QDCOUNT=1, all other counts zero
    pkt.extend_from_slice(&[0x00, 0x00]); // ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    pkt.extend_from_slice(name_bytes);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    pkt
}

fn parse_mdns_response(data: &[u8]) -> Vec<String> {
    if data.len() < 12 {
        return Vec::new();
    }

    let mut names = Vec::new();

    let _flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut offset = 12;

    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset);
        if offset == 0 || offset + 4 > data.len() {
            return names;
        }
        offset += 4; // QTYPE + QCLASS
    }

    let total_rrs = ancount + nscount + arcount;
    for _ in 0..total_rrs {
        if offset >= data.len() {
            break;
        }

        let name = read_dns_name(data, offset);
        offset = skip_dns_name(data, offset);
        if offset == 0 || offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            break;
        }

        match rtype {
            12 => {
                // PTR rdata is itself a DNS name
                let ptr_name = read_dns_name(data, offset);
                if !ptr_name.is_empty() && ptr_name != name {
                    names.push(ptr_name);
                }
            }
            33 => {
                // SRV rdata: priority(2) + weight(2) + port(2) + target name
                if rdlength > 6 {
                    let target = read_dns_name(data, offset + 6);
                    if !target.is_empty() {
                        names.push(target);
                    }
                }
            }
            _ => {
                if !name.is_empty()
                    && name.ends_with(".local")
                    && !name.contains("_tcp")
                    && !name.contains("_udp")
                {
                    names.push(name);
                }
            }
        }

        offset += rdlength;
    }

    names.retain(|n| {
        !n.is_empty()
            && n.contains('.')
            && !n.starts_with('_')
            && n != "local"
            && n.len() > 2
    });

    names
}

fn read_dns_name(data: &[u8], start: usize) -> String {
    let mut parts = Vec::new();
    let mut offset = start;
    let mut jumps = 0;

    loop {
        if offset >= data.len() || jumps > 10 {
            break;
        }

        let len = data[offset] as usize;
        if len == 0 {
            break;
        }

        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                break;
            }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            offset = ptr;
            jumps += 1;
            continue;
        }

        offset += 1;
        if offset + len > data.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&data[offset..offset + len]) {
            parts.push(s.to_string());
        }
        offset += len;
    }

    parts.join(".")
}

fn skip_dns_name(data: &[u8], start: usize) -> usize {
    let mut offset = start;
    loop {
        if offset >= data.len() {
            return 0;
        }
        let len = data[offset] as usize;
        if len == 0 {
            return offset + 1;
        }
        if len & 0xC0 == 0xC0 {
            return offset + 2;
        }
        offset += 1 + len;
    }
}
