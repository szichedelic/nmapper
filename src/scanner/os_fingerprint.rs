use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumbers};
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use rand::Rng;
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};

use crate::models::{OsDetails, OsFingerprint};

/// Fingerprint the OS of a target by analyzing TCP/IP stack behavior.
/// Requires at least one open port on the target.
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
    tcp_options: Vec<TcpOption>,
}

/// Send a SYN probe and capture the raw SYN-ACK response.
fn send_fingerprint_probe(target: Ipv4Addr, port: u16, verbose: bool) -> Option<RawResponse> {
    let protocol =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

    let (mut tx, mut rx) = match transport::transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            if verbose {
                eprintln!("  [!] OS fingerprint: failed to create raw socket: {e}");
            }
            return None;
        }
    };

    let mut rng = rand::thread_rng();
    let src_port: u16 = rng.gen_range(49152..65535);

    // Build SYN with TCP options to elicit a fingerprint-worthy response
    let mut tcp_buf = [0u8; 40]; // 20 header + 20 options
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buf)?;
    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(port);
    tcp_packet.set_sequence(rng.gen());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(10); // (40 bytes / 4)
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(65535);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_options(&[
        TcpOption::mss(1460),
        TcpOption::wscale(6),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::timestamp(12345, 0),
    ]);

    let checksum = pnet::packet::tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        &Ipv4Addr::UNSPECIFIED,
        &target,
    );
    tcp_packet.set_checksum(checksum);

    if tx.send_to(tcp_packet, IpAddr::V4(target)).is_err() {
        return None;
    }

    // Receive and analyze the SYN-ACK
    let timeout = Duration::from_millis(3000);
    let start = std::time::Instant::now();
    let mut iter = transport::tcp_packet_iter(&mut rx);

    while start.elapsed() < timeout {
        match iter.next_with_timeout(Duration::from_millis(200)) {
            Ok(Some((packet, addr))) => {
                if addr == IpAddr::V4(target)
                    && packet.get_source() == port
                    && packet.get_destination() == src_port
                {
                    let flags = packet.get_flags();
                    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                        let window_size = packet.get_window();
                        let tcp_options = packet.get_options().to_vec();

                        // Get TTL via ICMP probe
                        let ttl = estimate_ttl_from_icmp(target, timeout);
                        let df_bit = true; // Most modern OS set DF

                        // Send RST to close
                        let mut rst_buf = [0u8; 20];
                        if let Some(mut rst) = MutableTcpPacket::new(&mut rst_buf) {
                            rst.set_source(src_port);
                            rst.set_destination(port);
                            rst.set_sequence(packet.get_acknowledgement());
                            rst.set_data_offset(5);
                            rst.set_flags(TcpFlags::RST);
                            rst.set_window(0);
                            let ck = pnet::packet::tcp::ipv4_checksum(
                                &rst.to_immutable(),
                                &Ipv4Addr::UNSPECIFIED,
                                &target,
                            );
                            rst.set_checksum(ck);
                            let _ = tx.send_to(rst, IpAddr::V4(target));
                        }

                        return Some(RawResponse {
                            ttl,
                            window_size,
                            df_bit,
                            tcp_options,
                        });
                    }
                }
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    }

    None
}

/// Get TTL from an ICMP echo reply (IP header contains TTL).
fn estimate_ttl_from_icmp(target: Ipv4Addr, timeout: Duration) -> u8 {
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(SockProtocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    socket.set_read_timeout(Some(timeout)).ok();

    let mut buf = [0u8; 8];
    buf[0] = 8; // Echo request type
    buf[1] = 0; // Code
    buf[4] = 0x00; // Identifier
    buf[5] = 0x01;
    buf[6] = 0x00; // Sequence
    buf[7] = 0x01;

    // Calculate checksum
    let mut sum: u32 = 0;
    for chunk in buf.chunks(2) {
        let word = if chunk.len() == 2 {
            (chunk[0] as u32) << 8 | chunk[1] as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !sum as u16;
    buf[2] = (checksum >> 8) as u8;
    buf[3] = (checksum & 0xFF) as u8;

    let addr = SocketAddr::new(IpAddr::V4(target), 0);
    let addr = socket2::SockAddr::from(addr);
    if socket.send_to(&buf, &addr).is_err() {
        return 0;
    }

    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    match socket.recv(&mut recv_buf) {
        Ok(n) if n >= 20 => {
            // IP header TTL is at offset 8
            unsafe { recv_buf[8].assume_init() }
        }
        _ => 0,
    }
}

/// Analyze the raw response to determine the OS.
fn analyze_response(response: &RawResponse) -> OsFingerprint {
    let ttl = response.ttl;
    let window = response.window_size;
    let df = response.df_bit;
    let opts = format_tcp_options(&response.tcp_options);

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
            tcp_options_order: opts,
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

fn format_tcp_options(options: &[TcpOption]) -> String {
    options
        .iter()
        .map(|opt| {
            if opt.number == TcpOptionNumbers::NOP {
                "NOP".to_string()
            } else if opt.number == TcpOptionNumbers::MSS {
                "MSS".to_string()
            } else if opt.number == TcpOptionNumbers::WSCALE {
                "WS".to_string()
            } else if opt.number == TcpOptionNumbers::SACK_PERMITTED {
                "SACK".to_string()
            } else if opt.number == TcpOptionNumbers::TIMESTAMPS {
                "TS".to_string()
            } else if opt.number == TcpOptionNumbers::SACK {
                "SACK_DATA".to_string()
            } else {
                format!("OPT({})", opt.number.0)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}
