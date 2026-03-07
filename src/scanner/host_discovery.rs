use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use pnet::datalink;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use tokio::sync::Semaphore;
use tokio::time::sleep;

use crate::models::{DiscoveryMethod, HostStatus, TimingConfig};

pub struct DiscoveryResult {
    pub ip: IpAddr,
    pub status: HostStatus,
    pub mac_address: Option<MacAddr>,
}

pub async fn discover_hosts(
    targets: &[IpAddr],
    method: DiscoveryMethod,
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<DiscoveryResult> {
    match method {
        DiscoveryMethod::Skip => targets
            .iter()
            .map(|ip| DiscoveryResult {
                ip: *ip,
                status: HostStatus::Up,
                mac_address: None,
            })
            .collect(),
        DiscoveryMethod::Icmp => icmp_sweep(targets, timing, verbose).await,
        DiscoveryMethod::Arp => arp_sweep(targets, timing, verbose).await,
        DiscoveryMethod::Tcp => tcp_ping_sweep(targets, timing, verbose).await,
    }
}

async fn icmp_sweep(
    targets: &[IpAddr],
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<DiscoveryResult> {
    let semaphore = Arc::new(Semaphore::new(timing.max_parallel));
    let timeout = Duration::from_millis(timing.timeout_ms.min(800));
    let delay = Duration::from_millis(timing.delay_ms);

    let total = targets.len();
    let mut handles = Vec::with_capacity(total);

    for (i, &ip) in targets.iter().enumerate() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        if verbose && i > 0 && i % 50 == 0 {
            eprintln!("  [*] Discovery progress: {i}/{total}...");
        }

        handles.push(tokio::task::spawn_blocking(move || {
            let result = icmp_ping(ip, timeout);
            drop(permit);
            result
        }));

        if !delay.is_zero() {
            sleep(delay).await;
        }
    }

    let mut results = Vec::with_capacity(total);
    let mut up_count = 0;
    for handle in handles {
        if let Ok(result) = handle.await {
            if result.status == HostStatus::Up {
                up_count += 1;
                if verbose {
                    eprintln!("  [+] Host {} is up", result.ip);
                }
            }
            results.push(result);
        }
    }

    if verbose {
        eprintln!("  [*] ICMP sweep done: {up_count}/{total} hosts responded");
    }

    results
}

/// Our unique identifier embedded in each ICMP echo request.
fn icmp_id() -> u16 {
    (std::process::id() & 0xFFFF) as u16
}

fn icmp_ping(ip: IpAddr, timeout: Duration) -> DiscoveryResult {
    let status = match ip {
        IpAddr::V4(ipv4) => icmp_ping_v4(ipv4, timeout),
        IpAddr::V6(_) => HostStatus::Unknown,
    };
    DiscoveryResult {
        ip,
        status,
        mac_address: None,
    }
}

fn icmp_ping_v4(target: Ipv4Addr, timeout: Duration) -> HostStatus {
    // When running as root on macOS, use raw socket (more reliable for filtering).
    // DGRAM sockets can receive unsolicited ICMP causing false positives.
    if unsafe { libc::geteuid() } == 0 {
        return icmp_ping_raw(target, timeout);
    }
    icmp_ping_dgram(target, timeout)
}

/// ICMP ping using connected DGRAM socket (non-root macOS).
fn icmp_ping_dgram(target: Ipv4Addr, timeout: Duration) -> HostStatus {
    let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return HostStatus::Unknown,
    };

    socket.set_read_timeout(Some(timeout)).ok();
    socket.set_write_timeout(Some(timeout)).ok();

    // connect() filters traffic to only this target
    let addr = std::net::SocketAddr::new(IpAddr::V4(target), 0);
    let addr = socket2::SockAddr::from(addr);
    if socket.connect(&addr).is_err() {
        return HostStatus::Down;
    }

    let buf = build_icmp_echo_request();
    if socket.send(&buf).is_err() {
        return HostStatus::Down;
    }

    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    // DGRAM sockets on macOS strip the IP header, so ICMP starts at byte 0
    match socket.recv(&mut recv_buf) {
        Ok(n) if n >= 8 => {
            let icmp_type = unsafe { recv_buf[0].assume_init() };
            // 0 = Echo Reply
            if icmp_type == 0 {
                let id = unsafe {
                    ((recv_buf[4].assume_init() as u16) << 8) | recv_buf[5].assume_init() as u16
                };
                if id == icmp_id() {
                    return HostStatus::Up;
                }
            }
            HostStatus::Down
        }
        _ => HostStatus::Down,
    }
}

/// ICMP ping using raw socket (root). We get full IP+ICMP, so we parse both.
fn icmp_ping_raw(target: Ipv4Addr, timeout: Duration) -> HostStatus {
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(SockProtocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return HostStatus::Unknown,
    };

    socket.set_read_timeout(Some(timeout)).ok();
    socket.set_write_timeout(Some(timeout)).ok();

    let buf = build_icmp_echo_request();

    let dest = std::net::SocketAddr::new(IpAddr::V4(target), 0);
    let dest = socket2::SockAddr::from(dest);
    if socket.send_to(&buf, &dest).is_err() {
        return HostStatus::Down;
    }

    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    let deadline = std::time::Instant::now() + timeout;

    // Loop because raw sockets receive ALL ICMP traffic — we must filter
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return HostStatus::Down;
        }
        socket.set_read_timeout(Some(remaining)).ok();

        match socket.recv(&mut recv_buf) {
            Ok(n) if n >= 28 => {
                let ip_header_len = unsafe { (recv_buf[0].assume_init() & 0x0F) as usize * 4 };
                if n < ip_header_len + 8 {
                    continue;
                }

                let src_ip = unsafe {
                    Ipv4Addr::new(
                        recv_buf[12].assume_init(),
                        recv_buf[13].assume_init(),
                        recv_buf[14].assume_init(),
                        recv_buf[15].assume_init(),
                    )
                };
                if src_ip != target {
                    continue;
                }

                // ICMP starts after the IP header
                let icmp_type = unsafe { recv_buf[ip_header_len].assume_init() };

                // Type 0 = Echo Reply
                if icmp_type == 0 {
                    let id = unsafe {
                        let hi = recv_buf[ip_header_len + 4].assume_init() as u16;
                        let lo = recv_buf[ip_header_len + 5].assume_init() as u16;
                        (hi << 8) | lo
                    };
                    if id == icmp_id() {
                        return HostStatus::Up;
                    }
                }

                // Type 3 = Destination Unreachable from this source -> host is down
                if icmp_type == 3 {
                    return HostStatus::Down;
                }

                continue;
            }
            Ok(_) => continue,
            Err(_) => return HostStatus::Down,
        }
    }
}

fn build_icmp_echo_request() -> [u8; 8] {
    let mut buf = [0u8; 8];
    if let Some(mut echo) = MutableEchoRequestPacket::new(&mut buf) {
        echo.set_icmp_type(IcmpTypes::EchoRequest);
        echo.set_identifier(icmp_id());
        echo.set_sequence_number(1);
        let raw = echo.packet().to_vec();
        let cksum = internet_checksum(&raw);
        echo.set_checksum(cksum);
    }
    buf
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

async fn arp_sweep(
    targets: &[IpAddr],
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<DiscoveryResult> {
    let interfaces = datalink::interfaces();
    let interface = match interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
    {
        Some(iface) => iface,
        None => {
            eprintln!("[!] No suitable interface for ARP scan, falling back to ICMP");
            return icmp_sweep(targets, timing, verbose).await;
        }
    };

    let source_mac = interface.mac.unwrap_or(MacAddr::zero());
    let source_ip = match interface.ips.iter().find_map(|ip| match ip.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }) {
        Some(ip) => ip,
        None => {
            eprintln!("[!] No IPv4 address on interface, falling back to ICMP");
            return icmp_sweep(targets, timing, verbose).await;
        }
    };

    if verbose {
        eprintln!(
            "[*] ARP scan via {} ({source_ip}, {source_mac})",
            interface.name
        );
    }

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => {
            eprintln!("[!] Failed to open datalink channel, falling back to ICMP");
            return icmp_sweep(targets, timing, verbose).await;
        }
    };

    let ipv4_targets: Vec<Ipv4Addr> = targets
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .collect();

    for &target_ip in &ipv4_targets {
        let mut eth_buf = [0u8; 42];
        if let Some(mut eth_packet) = MutableEthernetPacket::new(&mut eth_buf) {
            eth_packet.set_destination(MacAddr::broadcast());
            eth_packet.set_source(source_mac);
            eth_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_buf = [0u8; 28];
            if let Some(mut arp_packet) = MutableArpPacket::new(&mut arp_buf) {
                arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_packet.set_protocol_type(EtherTypes::Ipv4);
                arp_packet.set_hw_addr_len(6);
                arp_packet.set_proto_addr_len(4);
                arp_packet.set_operation(ArpOperations::Request);
                arp_packet.set_sender_hw_addr(source_mac);
                arp_packet.set_sender_proto_addr(source_ip);
                arp_packet.set_target_hw_addr(MacAddr::zero());
                arp_packet.set_target_proto_addr(target_ip);

                eth_packet.set_payload(arp_packet.packet());
            }

            tx.send_to(eth_packet.packet(), None);
        }
    }

    eprintln!(
        "  [*] Sent {} ARP requests, collecting replies...",
        ipv4_targets.len()
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut seen: std::collections::HashMap<IpAddr, MacAddr> = std::collections::HashMap::new();

    while tokio::time::Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if packet.len() > 14 {
                    if let Some(arp) = ArpPacket::new(&packet[14..]) {
                        if arp.get_operation() == ArpOperations::Reply {
                            let sender_ip = IpAddr::V4(arp.get_sender_proto_addr());
                            let sender_mac = arp.get_sender_hw_addr();
                            if !seen.contains_key(&sender_ip) {
                                seen.insert(sender_ip, sender_mac);
                                if verbose {
                                    eprintln!(
                                        "  [+] Host {} is up (ARP from {})",
                                        sender_ip, sender_mac
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
            }
        }
    }

    eprintln!("  [*] ARP sweep done: {} hosts responded", seen.len());

    targets
        .iter()
        .map(|&ip| DiscoveryResult {
            ip,
            status: if seen.contains_key(&ip) {
                HostStatus::Up
            } else {
                HostStatus::Down
            },
            mac_address: seen.get(&ip).copied(),
        })
        .collect()
}

async fn tcp_ping_sweep(
    targets: &[IpAddr],
    timing: &TimingConfig,
    verbose: bool,
) -> Vec<DiscoveryResult> {
    let semaphore = Arc::new(Semaphore::new(timing.max_parallel));
    let timeout = Duration::from_millis(timing.timeout_ms.min(1000));
    let delay = Duration::from_millis(timing.delay_ms);

    let mut handles = Vec::new();

    for &ip in targets {
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        handles.push(tokio::spawn(async move {
            let result = tcp_ping(ip, timeout, verbose).await;
            drop(permit);
            result
        }));

        if !delay.is_zero() {
            sleep(delay).await;
        }
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    results
}

async fn tcp_ping(ip: IpAddr, timeout: Duration, verbose: bool) -> DiscoveryResult {
    let ping_ports = [80, 443];

    for port in ping_ports {
        let addr = std::net::SocketAddr::new(ip, port);
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                if verbose {
                    eprintln!("  [+] Host {ip} is up (TCP to port {port})");
                }
                return DiscoveryResult {
                    ip,
                    status: HostStatus::Up,
                    mac_address: None,
                };
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                if msg.contains("refused") {
                    if verbose {
                        eprintln!("  [+] Host {ip} is up (RST from port {port})");
                    }
                    return DiscoveryResult {
                        ip,
                        status: HostStatus::Up,
                        mac_address: None,
                    };
                }
            }
            Err(_) => continue,
        }
    }

    DiscoveryResult {
        ip,
        status: HostStatus::Down,
        mac_address: None,
    }
}
