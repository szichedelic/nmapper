use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{self, TransportChannelType, TransportProtocol};
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

/// TCP SYN (half-open) scan using batch send-then-receive pattern.
/// Sends all SYN packets first, then collects responses.
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

    let protocol =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

    let (mut tx, mut rx) = match transport::transport_channel(65536, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            if verbose {
                eprintln!("  [!] Failed to create raw socket: {e} (need root?)");
                eprintln!("  [!] Falling back to TCP connect scan");
            }
            return connect_scan(target, ports, timing, verbose).await;
        }
    };

    let mut rng = rand::thread_rng();

    // src port → dst port map for correlating responses to probes
    let mut port_map: HashMap<u16, u16> = HashMap::new();
    // All ports start as Filtered; updated when responses arrive
    let mut results_map: HashMap<u16, PortState> = HashMap::new();
    for &port in ports {
        results_map.insert(port, PortState::Filtered);
    }

    // Phase 1: Send all SYN packets in rapid succession
    let delay = Duration::from_millis(timing.delay_ms);
    for &port in ports {
        let src_port: u16 = rng.gen_range(49152..65535);
        port_map.insert(src_port, port);

        let mut tcp_buf = [0u8; 20];
        if let Some(mut tcp_packet) = MutableTcpPacket::new(&mut tcp_buf) {
            tcp_packet.set_source(src_port);
            tcp_packet.set_destination(port);
            tcp_packet.set_sequence(rng.gen());
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(64240);
            tcp_packet.set_urgent_ptr(0);

            let checksum = pnet::packet::tcp::ipv4_checksum(
                &tcp_packet.to_immutable(),
                &Ipv4Addr::UNSPECIFIED,
                &target_v4,
            );
            tcp_packet.set_checksum(checksum);

            let _ = tx.send_to(tcp_packet, IpAddr::V4(target_v4));
        }

        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }

    // Phase 2: Collect responses
    let receive_timeout = Duration::from_millis(timing.timeout_ms);
    let start = std::time::Instant::now();
    let mut iter = transport::tcp_packet_iter(&mut rx);
    let mut responded = 0;

    while start.elapsed() < receive_timeout && responded < ports.len() {
        match iter.next_with_timeout(Duration::from_millis(100)) {
            Ok(Some((packet, addr))) => {
                if addr != IpAddr::V4(target_v4) {
                    continue;
                }

                let dst_port = packet.get_destination();
                if let Some(&target_port) = port_map.get(&dst_port) {
                    let flags = packet.get_flags();
                    let state = if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                        // Send RST to close the half-open connection
                        send_rst(
                            &mut tx,
                            target_v4,
                            dst_port,
                            packet.get_source(),
                            packet.get_acknowledgement(),
                        );
                        if verbose {
                            eprintln!("  [+] {target}:{target_port} - open (SYN-ACK)");
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
            Ok(None) => continue,
            Err(_) => break,
        }
    }

    // Build sorted results
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

fn send_rst(
    tx: &mut transport::TransportSender,
    target: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
) {
    let mut tcp_buf = [0u8; 20];
    if let Some(mut tcp_packet) = MutableTcpPacket::new(&mut tcp_buf) {
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(seq);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::RST);
        tcp_packet.set_window(0);

        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &Ipv4Addr::UNSPECIFIED,
            &target,
        );
        tcp_packet.set_checksum(checksum);

        let _ = tx.send_to(tcp_packet, IpAddr::V4(target));
    }
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
