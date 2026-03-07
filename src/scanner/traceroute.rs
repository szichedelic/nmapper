use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::models::TracerouteHop;

const MAX_HOPS: u8 = 30;
const TIMEOUT_MS: u64 = 1000;
const DST_PORT: u16 = 33434;

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
        send_socket.set_ttl(ttl as u32).ok();
        let dest = SocketAddr::new(IpAddr::V4(target), DST_PORT + ttl as u16);
        let start = Instant::now();

        if send_socket.send_to(&[0u8; 32], dest).is_err() {
            hops.push(TracerouteHop {
                ttl,
                ip: None,
                hostname: None,
                rtt_ms: None,
            });
            continue;
        }

        let mut buf: [MaybeUninit<u8>; 512] = unsafe { MaybeUninit::uninit().assume_init() };

        match recv_socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                let hop_ip = match addr.as_socket_ipv4() {
                    Some(v4) => IpAddr::V4(*v4.ip()),
                    None => {
                        hops.push(TracerouteHop {
                            ttl,
                            ip: None,
                            hostname: None,
                            rtt_ms: None,
                        });
                        continue;
                    }
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

                if reached_target {
                    break;
                }

                if n >= 28 {
                    let ip_hdr_len = unsafe { (buf[0].assume_init() & 0x0F) as usize * 4 };
                    if n > ip_hdr_len {
                        let icmp_type = unsafe { buf[ip_hdr_len].assume_init() };
                        if icmp_type == 3 {
                            break;
                        }
                    }
                }
            }
            Err(_) => {
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
