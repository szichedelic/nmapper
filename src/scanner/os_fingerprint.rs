use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use rand::Rng;

use crate::models::{OsDetails, OsFingerprint};

/// Fingerprint the OS of a target by analyzing TCP/IP stack behavior.
pub fn fingerprint_os(target: IpAddr, open_port: u16, verbose: bool) -> Option<OsFingerprint> {
    let target_v4 = match target {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            if verbose {
                eprintln!("  [!] OS fingerprinting not supported for IPv6");
            }
            return None;
        }
    };

    let response = send_fingerprint_probe(target_v4, open_port, verbose)?;
    let fp = analyze_response(&response);

    if verbose {
        eprintln!(
            "  [*] OS fingerprint for {target}: {} (confidence: {:.0}%)",
            fp.name,
            fp.confidence * 100.0
        );
        eprintln!(
            "      TTL={}, Window={}, DF={}, TCP opts={}",
            fp.details.ttl, fp.details.window_size, fp.details.df_bit, fp.details.tcp_options_order
        );
    }

    Some(fp)
}

struct RawResponse {
    ttl: u8,
    window_size: u16,
    df_bit: bool,
    tcp_options_str: String,
}

fn get_source_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((target, 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

fn resolve_mac(
    interface: &datalink::NetworkInterface,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target: Ipv4Addr,
) -> Option<MacAddr> {
    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => return None,
    };

    let mut buf = [0u8; 42];
    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&src_mac.octets());
    buf[12..14].copy_from_slice(&[0x08, 0x06]);
    buf[14..16].copy_from_slice(&[0x00, 0x01]);
    buf[16..18].copy_from_slice(&[0x08, 0x00]);
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&[0x00, 0x01]);
    buf[22..28].copy_from_slice(&src_mac.octets());
    buf[28..32].copy_from_slice(&src_ip.octets());
    buf[32..38].copy_from_slice(&[0x00; 6]);
    buf[38..42].copy_from_slice(&target.octets());

    tx.send_to(&buf, None);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if frame.len() < 42 {
                    continue;
                }
                if frame[12..14] != [0x08, 0x06] || frame[20..22] != [0x00, 0x02] {
                    continue;
                }
                if frame[28..32] == target.octets() {
                    return Some(MacAddr::new(
                        frame[22], frame[23], frame[24], frame[25], frame[26], frame[27],
                    ));
                }
            }
            Err(_) => continue,
        }
    }
    None
}

fn get_default_gateway() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("gateway:") {
            let gw = trimmed.strip_prefix("gateway:")?.trim();
            return gw.parse().ok();
        }
    }
    None
}

fn get_next_hop(interface: &datalink::NetworkInterface, target: Ipv4Addr) -> Ipv4Addr {
    for ip_net in &interface.ips {
        if let IpAddr::V4(v4) = ip_net.ip() {
            let prefix = ip_net.prefix();
            let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
            if u32::from(v4) & mask == u32::from(target) & mask {
                return target;
            }
        }
    }
    get_default_gateway().unwrap_or(target)
}

/// Send a SYN probe with TCP options via BPF and capture the SYN-ACK response.
fn send_fingerprint_probe(target: Ipv4Addr, port: u16, verbose: bool) -> Option<RawResponse> {
    let src_ip = get_source_ip(target)?;

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| {
            iface.is_up()
                && !iface.is_loopback()
                && iface.ips.iter().any(|ip| ip.ip() == IpAddr::V4(src_ip))
        })?;

    let src_mac = match interface.mac {
        Some(mac) if mac != MacAddr::zero() => mac,
        _ => return None,
    };

    let next_hop = get_next_hop(&interface, target);
    let dst_mac = resolve_mac(&interface, src_mac, src_ip, next_hop)?;

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(200)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => return None,
    };

    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(49152..65535);

    // Build SYN with TCP options: 14 (eth) + 20 (ip) + 40 (tcp w/ options) = 74 bytes
    let mut buf = [0u8; 74];

    // Ethernet header
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(dst_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    // IPv4 header
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[14..34]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(60); // 20 IP + 40 TCP
        ip.set_identification(rng.gen());
        ip.set_flags(0x02); // DF
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(target);
        let cksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(cksum);
    }

    // TCP header with options (40 bytes)
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[34..74]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(port);
        tcp.set_sequence(rng.gen());
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(10); // 40 bytes / 4
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(65535);
        tcp.set_urgent_ptr(0);

        // Manually write TCP options into the buffer after the 20-byte header
        // MSS (4 bytes): kind=2, len=4, value=1460
        buf[54] = 2;
        buf[55] = 4;
        buf[56] = (1460 >> 8) as u8;
        buf[57] = (1460 & 0xff) as u8;
        // SACK Permitted (2 bytes): kind=4, len=2
        buf[58] = 4;
        buf[59] = 2;
        // Timestamp (10 bytes): kind=8, len=10, tsval=12345, tsecr=0
        buf[60] = 8;
        buf[61] = 10;
        let ts: u32 = 12345;
        buf[62..66].copy_from_slice(&ts.to_be_bytes());
        buf[66..70].copy_from_slice(&0u32.to_be_bytes());
        // NOP (1 byte): kind=1
        buf[70] = 1;
        // Window Scale (3 bytes): kind=3, len=3, shift=6
        buf[71] = 3;
        buf[72] = 3;
        buf[73] = 6;

        // Reparse to compute checksum with options included
        let tcp = MutableTcpPacket::new(&mut buf[34..74]).unwrap();
        let cksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &target);
        // Write checksum at offset 16-17 within TCP header
        buf[34 + 16] = (cksum >> 8) as u8;
        buf[34 + 17] = (cksum & 0xff) as u8;
    }

    tx.send_to(&buf, None);

    // Receive SYN-ACK
    let timeout = Duration::from_millis(3000);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        match rx.next() {
            Ok(frame) => {
                let eth = match EthernetPacket::new(frame) {
                    Some(e) => e,
                    None => continue,
                };
                if eth.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }

                let ip = match Ipv4Packet::new(eth.payload()) {
                    Some(i) => i,
                    None => continue,
                };
                if ip.get_source() != target || ip.get_destination() != src_ip {
                    continue;
                }
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                    continue;
                }

                let ip_hdr_len = (ip.get_header_length() as usize) * 4;
                let tcp_data = &eth.payload()[ip_hdr_len..];
                let tcp = match TcpPacket::new(tcp_data) {
                    Some(t) => t,
                    None => continue,
                };

                if tcp.get_source() != port || tcp.get_destination() != src_port {
                    continue;
                }

                let flags = tcp.get_flags();
                if flags & TcpFlags::SYN == 0 || flags & TcpFlags::ACK == 0 {
                    continue;
                }

                let ttl = ip.get_ttl();
                let window_size = tcp.get_window();
                let df_bit = ip.get_flags() & 0x02 != 0;
                let tcp_options_str = parse_tcp_options_safe(tcp_data);

                return Some(RawResponse {
                    ttl,
                    window_size,
                    df_bit,
                    tcp_options_str,
                });
            }
            Err(_) => continue,
        }
    }

    if verbose {
        eprintln!("  [!] OS fingerprint: no SYN-ACK received");
    }
    None
}

/// Parse TCP options directly from raw bytes to avoid pnet panics on malformed data.
fn parse_tcp_options_safe(tcp_data: &[u8]) -> String {
    if tcp_data.len() < 20 {
        return String::new();
    }

    let data_offset = (tcp_data[12] >> 4) as usize * 4;
    if data_offset <= 20 || data_offset > tcp_data.len() {
        return String::new();
    }

    let options = &tcp_data[20..data_offset];
    let mut result = Vec::new();
    let mut i = 0;

    while i < options.len() {
        match options[i] {
            0 => break, // End of options
            1 => {
                result.push("NOP".to_string());
                i += 1;
            }
            2 => {
                result.push("MSS".to_string());
                if i + 1 < options.len() {
                    i += options[i + 1] as usize;
                } else {
                    break;
                }
            }
            3 => {
                result.push("WS".to_string());
                if i + 1 < options.len() {
                    i += options[i + 1] as usize;
                } else {
                    break;
                }
            }
            4 => {
                result.push("SACK".to_string());
                if i + 1 < options.len() {
                    i += options[i + 1] as usize;
                } else {
                    break;
                }
            }
            5 => {
                result.push("SACK_DATA".to_string());
                if i + 1 < options.len() {
                    i += options[i + 1] as usize;
                } else {
                    break;
                }
            }
            8 => {
                result.push("TS".to_string());
                if i + 1 < options.len() {
                    i += options[i + 1] as usize;
                } else {
                    break;
                }
            }
            kind => {
                result.push(format!("OPT({kind})"));
                if i + 1 < options.len() && options[i + 1] >= 2 {
                    i += options[i + 1] as usize;
                } else {
                    break;
                }
            }
        }
    }

    result.join(",")
}

fn analyze_response(response: &RawResponse) -> OsFingerprint {
    let ttl = response.ttl;
    let window = response.window_size;
    let df = response.df_bit;
    let opts = &response.tcp_options_str;

    let initial_ttl = normalize_ttl(ttl);

    let mut candidates: Vec<(&str, f32)> = Vec::new();

    // Linux
    let mut linux_score: f32 = 0.0;
    if initial_ttl == 64 {
        linux_score += 0.4;
    }
    if window == 65535 || window == 29200 || window == 5840 || window == 14600 {
        linux_score += 0.2;
    }
    if df {
        linux_score += 0.1;
    }
    if opts.contains("MSS") && opts.contains("SACK") && opts.contains("TS") {
        linux_score += 0.2;
    }
    candidates.push(("Linux", linux_score));

    // Windows
    let mut windows_score: f32 = 0.0;
    if initial_ttl == 128 {
        windows_score += 0.4;
    }
    if window == 65535 || window == 8192 || window == 16384 {
        windows_score += 0.2;
    }
    if df {
        windows_score += 0.1;
    }
    candidates.push(("Windows", windows_score));

    // macOS / iOS
    let mut macos_score: f32 = 0.0;
    if initial_ttl == 64 {
        macos_score += 0.3;
    }
    if window == 65535 {
        macos_score += 0.3;
    }
    if df {
        macos_score += 0.1;
    }
    candidates.push(("macOS/iOS", macos_score));

    // FreeBSD
    let mut freebsd_score: f32 = 0.0;
    if initial_ttl == 64 {
        freebsd_score += 0.3;
    }
    if window == 65535 {
        freebsd_score += 0.2;
    }
    candidates.push(("FreeBSD", freebsd_score));

    // Network device / IoT
    let mut iot_score: f32 = 0.0;
    if initial_ttl == 255 {
        iot_score += 0.5;
    }
    if window < 4096 {
        iot_score += 0.3;
    }
    candidates.push(("Network Device/IoT", iot_score));

    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let (name, confidence) = candidates.first().unwrap();

    OsFingerprint {
        name: name.to_string(),
        confidence: *confidence,
        details: OsDetails {
            ttl,
            window_size: window,
            df_bit: df,
            tcp_options_order: opts.clone(),
        },
    }
}

fn normalize_ttl(ttl: u8) -> u8 {
    match ttl {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}
