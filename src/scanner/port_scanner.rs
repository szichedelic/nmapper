use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use pnet::datalink::{self, Channel::Ethernet, MacAddr};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use rand::Rng;
use tokio::sync::Semaphore;
use tokio::time::sleep;

use crate::models::{PortResult, PortState, Protocol, ScanType, TimingConfig};

pub async fn scan_ports(
    target: IpAddr,
    ports: &[u16],
    scan_type: ScanType,
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<PortResult> {
    match scan_type {
        ScanType::Syn => syn_scan(target, ports, timing, verbose).await,
        ScanType::Connect => connect_scan(target, ports, timing, verbose).await,
        ScanType::Udp => udp_scan(target, ports, timing, verbose).await,
    }
}

/// Determine the local source IP the OS would use to reach the target.
fn get_source_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((target, 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// Resolve the gateway MAC address by sending an ARP request via the datalink channel.
fn resolve_gateway_mac(
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

    // Build ARP request: 14 (eth) + 28 (arp) = 42 bytes
    let mut buf = [0u8; 42];

    // Ethernet header
    buf[0..6].copy_from_slice(&[0xff; 6]); // broadcast dest
    buf[6..12].copy_from_slice(&src_mac.octets());
    buf[12..14].copy_from_slice(&[0x08, 0x06]); // ARP ethertype

    // ARP payload
    buf[14..16].copy_from_slice(&[0x00, 0x01]); // hardware type: Ethernet
    buf[16..18].copy_from_slice(&[0x08, 0x00]); // protocol type: IPv4
    buf[18] = 6; // hardware addr len
    buf[19] = 4; // protocol addr len
    buf[20..22].copy_from_slice(&[0x00, 0x01]); // operation: request
    buf[22..28].copy_from_slice(&src_mac.octets()); // sender MAC
    buf[28..32].copy_from_slice(&src_ip.octets()); // sender IP
    buf[32..38].copy_from_slice(&[0x00; 6]); // target MAC (unknown)
    buf[38..42].copy_from_slice(&target.octets()); // target IP

    tx.send_to(&buf, None);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if frame.len() < 42 {
                    continue;
                }
                // Check it's an ARP reply (ethertype 0x0806, operation 0x0002)
                if frame[12..14] != [0x08, 0x06] || frame[20..22] != [0x00, 0x02] {
                    continue;
                }
                // Check sender IP matches our target
                if frame[28..32] == target.octets() {
                    let mac = MacAddr::new(
                        frame[22], frame[23], frame[24], frame[25], frame[26], frame[27],
                    );
                    return Some(mac);
                }
            }
            Err(_) => continue,
        }
    }

    None
}

/// Get the default gateway IP from the routing table.
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

/// Determine whether target is on the local subnet (ARP directly) or remote (ARP the gateway).
fn get_next_hop_ip(
    interface: &datalink::NetworkInterface,
    target: Ipv4Addr,
) -> Ipv4Addr {
    for ip_net in &interface.ips {
        if let IpAddr::V4(v4) = ip_net.ip() {
            let prefix = ip_net.prefix();
            let mask = if prefix == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix)
            };
            let net_addr = u32::from(v4) & mask;
            let target_net = u32::from(target) & mask;
            if net_addr == target_net {
                return target; // On same subnet, ARP the target directly
            }
        }
    }
    get_default_gateway().unwrap_or(target)
}

/// TCP SYN (half-open) scan using BPF datalink channel.
/// On macOS, raw TCP sockets cannot receive incoming packets, so we use BPF
/// to send and receive raw Ethernet frames containing our TCP SYN probes.
async fn syn_scan(
    target: IpAddr,
    ports: &[u16],
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<PortResult> {
    let target_v4 = match target {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            if verbose {
                eprintln!("  [!] SYN scan not supported for IPv6, falling back to connect scan");
            }
            return connect_scan(target, ports, timing, verbose).await;
        }
    };

    let src_ip = match get_source_ip(target_v4) {
        Some(ip) => ip,
        None => {
            if verbose {
                eprintln!("  [!] Cannot determine source IP, falling back to connect scan");
            }
            return connect_scan(target, ports, timing, verbose).await;
        }
    };

    let interfaces = datalink::interfaces();
    let interface = match interfaces
        .into_iter()
        .find(|iface| {
            iface.is_up()
                && !iface.is_loopback()
                && iface
                    .ips
                    .iter()
                    .any(|ip| ip.ip() == IpAddr::V4(src_ip))
        }) {
        Some(iface) => iface,
        None => {
            if verbose {
                eprintln!("  [!] No suitable interface found, falling back to connect scan");
            }
            return connect_scan(target, ports, timing, verbose).await;
        }
    };

    let src_mac = match interface.mac {
        Some(mac) if mac != MacAddr::zero() => mac,
        _ => {
            if verbose {
                eprintln!("  [!] No MAC address on interface, falling back to connect scan");
            }
            return connect_scan(target, ports, timing, verbose).await;
        }
    };

    let next_hop = get_next_hop_ip(&interface, target_v4);
    let dst_mac = match resolve_gateway_mac(&interface, src_mac, src_ip, next_hop) {
        Some(mac) => mac,
        None => {
            if verbose {
                eprintln!("  [!] Cannot resolve MAC for {next_hop}, falling back to connect scan");
            }
            return connect_scan(target, ports, timing, verbose).await;
        }
    };

    if verbose {
        eprintln!(
            "  [*] SYN scan via {} (src={src_ip}, dst_mac={dst_mac})",
            interface.name
        );
    }

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => {
            if verbose {
                eprintln!("  [!] Failed to open datalink channel, falling back to connect scan");
            }
            return connect_scan(target, ports, timing, verbose).await;
        }
    };

    syn_scan_bpf(
        &mut tx, &mut rx, src_ip, src_mac, target_v4, dst_mac, ports, timing, verbose,
    )
}

#[allow(clippy::too_many_arguments)]
fn syn_scan_bpf(
    tx: &mut Box<dyn datalink::DataLinkSender>,
    rx: &mut Box<dyn datalink::DataLinkReceiver>,
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
    target_v4: Ipv4Addr,
    dst_mac: MacAddr,
    ports: &[u16],
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<PortResult> {
    let mut rng = rand::thread_rng();

    let mut port_map: HashMap<u16, u16> = HashMap::new();
    let mut results_map: HashMap<u16, PortState> = HashMap::new();
    for &port in ports {
        results_map.insert(port, PortState::Filtered);
    }

    // Send phase: blast SYN packets as raw Ethernet frames
    let delay = Duration::from_millis(timing.delay_ms);
    let mut ip_id: u16 = rng.gen();

    for &port in ports {
        let src_port: u16 = rng.gen_range(49152..65535);
        port_map.insert(src_port, port);

        // 14 (eth) + 20 (ip) + 20 (tcp) = 54 bytes
        let mut buf = [0u8; 54];

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
            ip.set_total_length(40); // 20 IP + 20 TCP
            ip.set_identification(ip_id);
            ip_id = ip_id.wrapping_add(1);
            ip.set_flags(0x02); // Don't Fragment
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(src_ip);
            ip.set_destination(target_v4);
            let cksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(cksum);
        }

        // TCP header
        {
            let mut tcp = MutableTcpPacket::new(&mut buf[34..54]).unwrap();
            tcp.set_source(src_port);
            tcp.set_destination(port);
            tcp.set_sequence(rng.gen());
            tcp.set_acknowledgement(0);
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_window(64240);
            tcp.set_urgent_ptr(0);
            let cksum = pnet::packet::tcp::ipv4_checksum(
                &tcp.to_immutable(),
                &src_ip,
                &target_v4,
            );
            tcp.set_checksum(cksum);
        }

        tx.send_to(&buf, None);

        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }

    // Receive phase: read raw Ethernet frames and parse TCP responses
    let receive_timeout = Duration::from_millis(timing.timeout_ms);
    let start = std::time::Instant::now();
    let mut responded = 0;

    while start.elapsed() < receive_timeout && responded < ports.len() {
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

                if ip.get_source() != target_v4 || ip.get_destination() != src_ip {
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

                let dst_port = tcp.get_destination();
                if let Some(&target_port) = port_map.get(&dst_port) {
                    let flags = tcp.get_flags();
                    let state = if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                        if verbose {
                            eprintln!("  [+] {target_v4}:{target_port} - open (SYN-ACK)");
                        }
                        PortState::Open
                    } else if flags & TcpFlags::RST != 0 {
                        PortState::Closed
                    } else {
                        continue;
                    };

                    results_map.insert(target_port, state);
                    responded += 1;
                }
            }
            Err(_) => {
                if start.elapsed() >= receive_timeout {
                    break;
                }
                continue;
            }
        }
    }

    let mut results: Vec<PortResult> = ports
        .iter()
        .map(|&port| PortResult {
            port,
            protocol: Protocol::Tcp,
            state: *results_map.get(&port).unwrap_or(&PortState::Filtered),
            service: None,
        })
        .collect();

    results.sort_by_key(|r| r.port);
    results
}

/// TCP Connect scan — full three-way handshake using tokio.
async fn connect_scan(
    target: IpAddr,
    ports: &[u16],
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<PortResult> {
    let semaphore = Arc::new(Semaphore::new(timing.max_parallel));
    let timeout = Duration::from_millis(timing.timeout_ms);
    let delay = Duration::from_millis(timing.delay_ms);

    let mut handles = Vec::new();

    for &port in ports {
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        handles.push(tokio::spawn(async move {
            let state = connect_probe(target, port, timeout).await;
            drop(permit);
            PortResult {
                port,
                protocol: Protocol::Tcp,
                state,
                service: None,
            }
        }));

        if !delay.is_zero() {
            sleep(delay).await;
        }
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            if verbose && result.state == PortState::Open {
                eprintln!("  [+] {target}:{} - open (connect)", result.port);
            }
            results.push(result);
        }
    }

    results.sort_by_key(|r| r.port);
    results
}

async fn connect_probe(target: IpAddr, port: u16, timeout: Duration) -> PortState {
    let addr = SocketAddr::new(target, port);
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("refused") {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
        Err(_) => PortState::Filtered,
    }
}

/// UDP scan — send empty datagrams and check for ICMP unreachable.
async fn udp_scan(
    target: IpAddr,
    ports: &[u16],
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<PortResult> {
    let semaphore = Arc::new(Semaphore::new(timing.max_parallel));
    let timeout = Duration::from_millis(timing.timeout_ms);
    let delay = Duration::from_millis(timing.delay_ms);

    let mut handles = Vec::new();

    for &port in ports {
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        handles.push(tokio::spawn(async move {
            let state = udp_probe(target, port, timeout).await;
            drop(permit);
            PortResult {
                port,
                protocol: Protocol::Udp,
                state,
                service: None,
            }
        }));

        if !delay.is_zero() {
            sleep(delay).await;
        }
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            if verbose && result.state == PortState::Open {
                eprintln!("  [+] {target}:{} - open|filtered (UDP)", result.port);
            }
            results.push(result);
        }
    }

    results.sort_by_key(|r| r.port);
    results
}

async fn udp_probe(target: IpAddr, port: u16, timeout: Duration) -> PortState {
    let addr = SocketAddr::new(target, port);
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return PortState::Filtered,
    };

    if socket.send_to(&[], addr).await.is_err() {
        return PortState::Filtered;
    }

    let mut buf = [0u8; 1024];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("refused") || msg.contains("unreachable") {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
        Err(_) => PortState::Open, // No response = open|filtered
    }
}
