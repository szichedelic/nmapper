use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use colored::Colorize;
use pnet::datalink;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

#[derive(Debug, Clone)]
pub struct PassiveDevice {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub protocols_seen: Vec<String>,
    pub _first_seen: std::time::Instant,
}

/// Run passive discovery — listen without sending any probes.
pub fn passive_discover(duration_secs: u64, verbose: bool) -> Vec<PassiveDevice> {
    let interfaces = datalink::interfaces();
    let interface = match interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
    {
        Some(iface) => iface,
        None => {
            eprintln!("[!] No suitable interface for passive capture");
            return Vec::new();
        }
    };

    eprintln!(
        "[*] Passive mode: listening on {} for {}s...",
        interface.name, duration_secs
    );

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };

    let (_tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(_tx, rx)) => (_tx, rx),
        _ => {
            eprintln!("[!] Failed to open datalink channel for passive capture");
            return Vec::new();
        }
    };

    let mut devices: HashMap<IpAddr, PassiveDevice> = HashMap::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(duration_secs);

    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    match eth.get_ethertype() {
                        EtherTypes::Arp => {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                let ip = IpAddr::V4(arp.get_sender_proto_addr());
                                let mac = arp.get_sender_hw_addr();

                                if !is_broadcast_ip(arp.get_sender_proto_addr()) {
                                    let device =
                                        devices.entry(ip).or_insert_with(|| PassiveDevice {
                                            ip,
                                            mac: Some(mac),
                                            protocols_seen: Vec::new(),
                                            _first_seen: std::time::Instant::now(),
                                        });
                                    if !device.protocols_seen.contains(&"ARP".to_string()) {
                                        device.protocols_seen.push("ARP".to_string());
                                        if verbose {
                                            eprintln!(
                                                "  [+] ARP: {} ({})",
                                                ip,
                                                mac
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                let src_ip = IpAddr::V4(ipv4.get_source());
                                let src_mac = eth.get_source();

                                if !is_broadcast_ip(ipv4.get_source())
                                    && !is_multicast_ip(ipv4.get_source())
                                {
                                    let device = devices
                                        .entry(src_ip)
                                        .or_insert_with(|| PassiveDevice {
                                            ip: src_ip,
                                            mac: Some(src_mac),
                                            protocols_seen: Vec::new(),
                                            _first_seen: std::time::Instant::now(),
                                        });

                                    if ipv4.get_next_level_protocol()
                                        == IpNextHeaderProtocols::Udp
                                    {
                                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                            let dst_port = udp.get_destination();
                                            let src_port = udp.get_source();

                                            if dst_port == 5353 || src_port == 5353 {
                                                if !device.protocols_seen.contains(&"mDNS".to_string()) {
                                                    device.protocols_seen.push("mDNS".to_string());
                                                    if verbose {
                                                        eprintln!("  [+] mDNS: {}", src_ip);
                                                    }
                                                }
                                            }
                                            if dst_port == 1900 || src_port == 1900 {
                                                if !device.protocols_seen.contains(&"SSDP".to_string()) {
                                                    device.protocols_seen.push("SSDP".to_string());
                                                    if verbose {
                                                        eprintln!("  [+] SSDP: {}", src_ip);
                                                    }
                                                }
                                            }
                                            if dst_port == 67
                                                || dst_port == 68
                                                || src_port == 67
                                                || src_port == 68
                                            {
                                                if !device.protocols_seen.contains(&"DHCP".to_string()) {
                                                    device.protocols_seen.push("DHCP".to_string());
                                                    if verbose {
                                                        eprintln!("  [+] DHCP: {}", src_ip);
                                                    }
                                                }
                                            }
                                            if dst_port == 53 || src_port == 53 {
                                                if !device.protocols_seen.contains(&"DNS".to_string()) {
                                                    device.protocols_seen.push("DNS".to_string());
                                                }
                                            }
                                            if dst_port == 123 || src_port == 123 {
                                                if !device.protocols_seen.contains(&"NTP".to_string()) {
                                                    device.protocols_seen.push("NTP".to_string());
                                                }
                                            }
                                        }
                                    }

                                    if ipv4.get_next_level_protocol()
                                        == IpNextHeaderProtocols::Tcp
                                    {
                                        if !device
                                            .protocols_seen
                                            .contains(&"TCP".to_string())
                                        {
                                            device.protocols_seen.push("TCP".to_string());
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => continue,
        }
    }

    let count = devices.len();
    eprintln!();
    eprintln!(
        "{}",
        format!("[*] Passive discovery complete: {count} device(s) found").bold()
    );

    for device in devices.values() {
        let mac_str = device
            .mac
            .map(|m| m.to_string())
            .unwrap_or_else(|| "?".to_string());
        println!(
            "  {} {} ({}) — seen via: {}",
            "+".green(),
            device.ip.to_string().cyan(),
            mac_str.dimmed(),
            device.protocols_seen.join(", ").yellow()
        );
    }

    devices.into_values().collect()
}

fn is_broadcast_ip(ip: Ipv4Addr) -> bool {
    ip == Ipv4Addr::BROADCAST || ip.octets()[3] == 255
}

fn is_multicast_ip(ip: Ipv4Addr) -> bool {
    ip.octets()[0] >= 224 && ip.octets()[0] <= 239
}
