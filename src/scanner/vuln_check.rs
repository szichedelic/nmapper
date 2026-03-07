use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use serde::Serialize;

use crate::models::PortResult;

#[derive(Debug, Clone, Serialize)]
pub struct VulnWarning {
    pub port: u16,
    pub severity: String,
    pub description: String,
}

/// Check for default credentials and open services on discovered ports.
pub fn check_vulnerabilities(
    target: IpAddr,
    ports: &[PortResult],
    verbose: bool,
) -> Vec<VulnWarning> {
    let mut warnings = Vec::new();
    let timeout = Duration::from_secs(5);

    for port in ports {
        if port.state != crate::models::PortState::Open {
            continue;
        }

        let svc_name = port
            .service
            .as_ref()
            .map(|s| s.name.as_str())
            .unwrap_or("unknown");

        match (port.port, svc_name) {
            (6379, _) | (_, "redis") => {
                if let Some(w) = check_redis_no_auth(target, port.port, timeout) {
                    warnings.push(w);
                }
            }
            (27017 | 27018, _) | (_, "mongodb") => {
                if let Some(w) = check_mongodb_no_auth(target, port.port, timeout) {
                    warnings.push(w);
                }
            }
            (23, _) | (_, "telnet") => {
                warnings.push(VulnWarning {
                    port: port.port,
                    severity: "medium".to_string(),
                    description: "Telnet service exposed (unencrypted protocol)".to_string(),
                });
                if let Some(w) = check_telnet_default_creds(target, port.port, timeout) {
                    warnings.push(w);
                }
            }
            (161, _) | (_, "snmp") => {
                if let Some(w) = check_snmp_default_community(target, port.port) {
                    warnings.push(w);
                }
            }
            (80 | 8080 | 8081 | 8000 | 8888 | 9090, _) | (_, "http" | "http-proxy" | "http-alt") => {
                if let Some(w) = check_http_default_creds(target, port.port, timeout) {
                    warnings.push(w);
                }
            }
            (21, _) | (_, "ftp") => {
                if let Some(w) = check_ftp_anonymous(target, port.port, timeout) {
                    warnings.push(w);
                }
            }
            _ => {}
        }

        if verbose && !warnings.is_empty() {
            let last = warnings.last().unwrap();
            eprintln!(
                "  [!] {} (port {}): {}",
                last.severity.to_uppercase(),
                last.port,
                last.description
            );
        }
    }

    warnings
}

fn check_redis_no_auth(target: IpAddr, port: u16, timeout: Duration) -> Option<VulnWarning> {
    let addr = SocketAddr::new(target, port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    stream.write_all(b"PING\r\n").ok()?;

    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if response.contains("+PONG") {
        return Some(VulnWarning {
            port,
            severity: "high".to_string(),
            description: "Redis accessible without authentication".to_string(),
        });
    }

    None
}

fn check_mongodb_no_auth(target: IpAddr, port: u16, timeout: Duration) -> Option<VulnWarning> {
    let addr = SocketAddr::new(target, port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    // Minimal MongoDB OP_QUERY for { isMaster: 1 } against admin.$cmd
    let is_master_bson = [
        0x17, 0x00, 0x00, 0x00, // BSON doc length (23 bytes)
        0x10,                   // int32 element type
        b'i', b's', b'M', b'a', b's', b't', b'e', b'r', 0x00, // key "isMaster\0"
        0x01, 0x00, 0x00, 0x00, // value: 1
        0x00,                   // document terminator
    ];

    let msg_len = (16 + 4 + 4 + 12 + 4 + 4 + is_master_bson.len()) as u32;
    let mut msg = Vec::with_capacity(msg_len as usize);
    msg.extend_from_slice(&msg_len.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes()); // requestID
    msg.extend_from_slice(&0u32.to_le_bytes()); // responseTo
    msg.extend_from_slice(&2004u32.to_le_bytes()); // opCode OP_QUERY
    msg.extend_from_slice(&0u32.to_le_bytes()); // flags
    msg.extend_from_slice(b"admin.$cmd\0");
    msg.extend_from_slice(&0u32.to_le_bytes()); // numberToSkip
    msg.extend_from_slice(&1u32.to_le_bytes()); // numberToReturn
    msg.extend_from_slice(&is_master_bson);

    stream.write_all(&msg).ok()?;

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).ok()?;

    if n > 36 {
        return Some(VulnWarning {
            port,
            severity: "high".to_string(),
            description: "MongoDB accessible without authentication".to_string(),
        });
    }

    None
}

fn check_telnet_default_creds(
    target: IpAddr,
    port: u16,
    timeout: Duration,
) -> Option<VulnWarning> {
    let creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("root", "root"),
        ("root", ""),
    ];

    let addr = SocketAddr::new(target, port);

    for (user, pass) in &creds {
        let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => s,
            Err(_) => return None,
        };
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf); // consume banner/login prompt

        let _ = stream.write_all(format!("{user}\r\n").as_bytes());
        std::thread::sleep(Duration::from_millis(500));

        let _ = stream.read(&mut buf); // consume password prompt

        let _ = stream.write_all(format!("{pass}\r\n").as_bytes());
        std::thread::sleep(Duration::from_millis(500));

        let n = stream.read(&mut buf).unwrap_or(0);
        let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();

        if n > 0
            && !response.contains("incorrect")
            && !response.contains("failed")
            && !response.contains("denied")
            && !response.contains("invalid")
            && !response.contains("error")
            && (response.contains('$')
                || response.contains('#')
                || response.contains('>')
                || response.contains("welcome"))
        {
            return Some(VulnWarning {
                port,
                severity: "critical".to_string(),
                description: format!(
                    "Telnet default credentials accepted: {user}/{pass}"
                ),
            });
        }
    }

    None
}

fn check_snmp_default_community(target: IpAddr, port: u16) -> Option<VulnWarning> {
    use std::net::UdpSocket;

    let communities = ["public", "private"];

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .ok();

    for community in &communities {
        let pkt = build_snmp_get(community);
        let addr = SocketAddr::new(target, port);
        socket.send_to(&pkt, addr).ok()?;

        let mut buf = [0u8; 2048];
        if let Ok(n) = socket.recv(&mut buf) {
            if n > 2 && buf[0] == 0x30 {
                return Some(VulnWarning {
                    port,
                    severity: "medium".to_string(),
                    description: format!(
                        "SNMP default community string accepted: '{community}'"
                    ),
                });
            }
        }
    }

    None
}

// Build a minimal SNMPv1 GET request for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0).
fn build_snmp_get(community: &str) -> Vec<u8> {
    let oid: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

    let mut varbind = Vec::new();
    varbind.push(0x30); // SEQUENCE
    let inner_len = 2 + oid.len() + 2; // OID TLV + NULL TLV
    varbind.push(inner_len as u8);
    varbind.push(0x06); // OID tag
    varbind.push(oid.len() as u8);
    varbind.extend_from_slice(oid);
    varbind.push(0x05); // NULL tag
    varbind.push(0x00);

    let mut varbind_list = Vec::new();
    varbind_list.push(0x30);
    varbind_list.push(varbind.len() as u8);
    varbind_list.extend_from_slice(&varbind);

    let request_id: &[u8] = &[0x01];
    let mut pdu = Vec::new();
    pdu.push(0x02); pdu.push(0x01); pdu.extend_from_slice(request_id); // request-id
    pdu.push(0x02); pdu.push(0x01); pdu.push(0x00); // error-status = 0
    pdu.push(0x02); pdu.push(0x01); pdu.push(0x00); // error-index = 0
    pdu.extend_from_slice(&varbind_list);

    let mut get_request = Vec::new();
    get_request.push(0xA0); // GetRequest-PDU tag
    get_request.push(pdu.len() as u8);
    get_request.extend_from_slice(&pdu);

    let mut msg = Vec::new();
    msg.push(0x02); msg.push(0x01); msg.push(0x00); // version = 0 (SNMPv1)
    msg.push(0x04); msg.push(community.len() as u8);
    msg.extend_from_slice(community.as_bytes());
    msg.extend_from_slice(&get_request);

    let mut packet = Vec::new();
    packet.push(0x30);
    packet.push(msg.len() as u8);
    packet.extend_from_slice(&msg);

    packet
}

fn check_http_default_creds(
    target: IpAddr,
    port: u16,
    timeout: Duration,
) -> Option<VulnWarning> {
    use std::io::Write;

    let addr = SocketAddr::new(target, port);

    let cred_pairs = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("root", "admin"),
    ];

    for (user, pass) in &cred_pairs {
        let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok();

        let creds = base64_encode(&format!("{user}:{pass}"));
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
            target, creds
        );

        stream.write_all(request.as_bytes()).ok()?;

        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).ok()?;
        let response = String::from_utf8_lossy(&buf[..n]);

        if let Some(status_line) = response.lines().next() {
            if status_line.contains(" 200 ") || status_line.contains(" 301 ") || status_line.contains(" 302 ") {
                // Confirm the endpoint actually requires auth by checking without credentials first;
                // only flag if a 401/403 is returned unauthenticated, confirming these are default creds.
                let mut check_stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
                check_stream.set_read_timeout(Some(timeout)).ok();
                let no_auth_req = format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    target
                );
                check_stream.write_all(no_auth_req.as_bytes()).ok()?;
                let n = check_stream.read(&mut buf).ok()?;
                let no_auth_resp = String::from_utf8_lossy(&buf[..n]);
                if let Some(status) = no_auth_resp.lines().next() {
                    if status.contains(" 401 ") || status.contains(" 403 ") {
                        return Some(VulnWarning {
                            port,
                            severity: "critical".to_string(),
                            description: format!(
                                "HTTP Basic Auth default credentials accepted: {user}/{pass}"
                            ),
                        });
                    }
                }
            }
        }
    }

    None
}

fn check_ftp_anonymous(target: IpAddr, port: u16, timeout: Duration) -> Option<VulnWarning> {
    let addr = SocketAddr::new(target, port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf); // consume banner

    stream.write_all(b"USER anonymous\r\n").ok()?;
    std::thread::sleep(Duration::from_millis(300));
    let n = stream.read(&mut buf).unwrap_or(0);
    let response = String::from_utf8_lossy(&buf[..n]);

    if response.starts_with("331") || response.starts_with("230") {
        stream.write_all(b"PASS anonymous@\r\n").ok()?;
        std::thread::sleep(Duration::from_millis(300));
        let n = stream.read(&mut buf).unwrap_or(0);
        let response = String::from_utf8_lossy(&buf[..n]);

        if response.starts_with("230") {
            return Some(VulnWarning {
                port,
                severity: "medium".to_string(),
                description: "FTP allows anonymous login".to_string(),
            });
        }
    }

    None
}

fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}
