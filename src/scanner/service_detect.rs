use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::sleep;

use crate::models::{PortResult, PortState, ServiceInfo, TimingConfig};

/// Run service/version detection on all open ports.
pub async fn detect_services(
    target: IpAddr,
    ports: &mut [PortResult],
    timing: &TimingConfig,
    verbose: bool,
) {
    let semaphore = Arc::new(Semaphore::new(timing.max_parallel));
    let timeout = Duration::from_millis(timing.timeout_ms * 2); // give service detection more time
    let delay = Duration::from_millis(timing.delay_ms);

    let mut handles = Vec::new();

    for port_result in ports.iter().filter(|p| p.state == PortState::Open) {
        let port = port_result.port;
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        handles.push(tokio::spawn(async move {
            let service = probe_service(target, port, timeout).await;
            drop(permit);
            (port, service)
        }));

        if !delay.is_zero() {
            sleep(delay).await;
        }
    }

    for handle in handles {
        if let Ok((port, service)) = handle.await {
            if let Some(port_result) = ports.iter_mut().find(|p| p.port == port) {
                if verbose {
                    if let Some(ref svc) = service {
                        let ver = svc.version.as_deref().unwrap_or("unknown version");
                        eprintln!("  [+] {target}:{port} - {}: {ver}", svc.name);
                    }
                }
                port_result.service = service;
            }
        }
    }
}

/// Probe a single port to identify the running service.
async fn probe_service(target: IpAddr, port: u16, timeout: Duration) -> Option<ServiceInfo> {
    let banner = grab_banner(target, port, timeout).await;

    if let Some(ref banner_text) = banner {
        if let Some(service) = identify_from_banner(banner_text, port) {
            return Some(service);
        }
    }

    if let Some(service) = protocol_probe(target, port, timeout).await {
        return Some(service);
    }

    // Fall back to port-number-based name with the raw banner attached
    Some(ServiceInfo {
        name: port_to_service_name(port).to_string(),
        version: None,
        banner,
        tls_info: None,
    })
}

async fn grab_banner(target: IpAddr, port: u16, timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(target, port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 4096];
    let banner_timeout = Duration::from_millis(2000);
    match tokio::time::timeout(banner_timeout, async {
        let mut stream = stream;
        stream.read(&mut buf).await
    })
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        _ => None,
    }
}

async fn protocol_probe(target: IpAddr, port: u16, timeout: Duration) -> Option<ServiceInfo> {
    let addr = SocketAddr::new(target, port);

    if matches!(
        port,
        80 | 443 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888 | 9090
    ) {
        if let Some(service) = http_probe(addr, timeout).await {
            return Some(service);
        }
    }

    if port == 53 {
        if let Some(service) = dns_version_probe(target, port).await {
            return Some(service);
        }
    }

    if port == 1883 || port == 8883 {
        if let Some(service) = mqtt_probe(addr, timeout).await {
            return Some(service);
        }
    }

    if port == 23 || port == 2323 {
        if let Some(service) = telnet_probe(addr, timeout).await {
            return Some(service);
        }
    }

    if port == 6379 {
        if let Some(service) = redis_probe(addr, timeout).await {
            return Some(service);
        }
    }

    if port == 445 {
        if let Some(service) = smb_probe(addr, timeout).await {
            return Some(service);
        }
    }

    if let Some(service) = http_probe(addr, timeout).await {
        return Some(service);
    }

    None
}

/// Query DNS TXT record for version.bind to get DNS server version.
async fn dns_version_probe(target: IpAddr, port: u16) -> Option<ServiceInfo> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let dest = SocketAddr::new(target, port);

    // DNS query for version.bind TXT CH
    let mut query = Vec::new();
    query.extend_from_slice(&[0x00, 0x01]); // ID
    query.extend_from_slice(&[0x00, 0x00]); // Flags: standard query
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    // QNAME: version.bind
    query.push(7);
    query.extend_from_slice(b"version");
    query.push(4);
    query.extend_from_slice(b"bind");
    query.push(0);
    query.extend_from_slice(&[0x00, 0x10]); // QTYPE: TXT
    query.extend_from_slice(&[0x00, 0x03]); // QCLASS: CH

    socket.send_to(&query, dest).await.ok()?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(
        Duration::from_secs(3),
        socket.recv(&mut buf),
    )
    .await
    .ok()?
    .ok()?;

    if n < 12 {
        return None;
    }

    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 {
        return Some(ServiceInfo {
            name: "dns".to_string(),
            version: None,
            banner: None,
            tls_info: None,
        });
    }

    let version = extract_dns_txt(&buf[..n]);

    Some(ServiceInfo {
        name: "dns".to_string(),
        version,
        banner: None,
        tls_info: None,
    })
}

fn extract_dns_txt(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    // Skip header (12 bytes)
    let mut offset = 12;
    // Skip question section
    while offset < data.len() {
        if data[offset] == 0 {
            offset += 5; // null + QTYPE(2) + QCLASS(2)
            break;
        }
        if data[offset] & 0xC0 == 0xC0 {
            offset += 6; // pointer(2) + QTYPE(2) + QCLASS(2)
            break;
        }
        offset += 1 + data[offset] as usize;
    }
    // Parse answer RR
    if offset + 12 > data.len() {
        return None;
    }
    // Skip name
    if data[offset] & 0xC0 == 0xC0 {
        offset += 2;
    } else {
        while offset < data.len() && data[offset] != 0 {
            offset += 1 + data[offset] as usize;
        }
        offset += 1;
    }
    if offset + 10 > data.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
    offset += 10;
    if offset + rdlength > data.len() || rdlength < 2 {
        return None;
    }
    // TXT record: first byte is length of text
    let txt_len = data[offset] as usize;
    offset += 1;
    if offset + txt_len > data.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&data[offset..offset + txt_len]).to_string())
}

/// MQTT CONNECT probe to detect MQTT brokers.
async fn mqtt_probe(addr: SocketAddr, timeout: Duration) -> Option<ServiceInfo> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // MQTT CONNECT packet (minimal)
    let connect_packet: &[u8] = &[
        0x10, // CONNECT packet type
        0x10, // Remaining length (16)
        0x00, 0x04, b'M', b'Q', b'T', b'T', // Protocol Name
        0x04, // Protocol Level (MQTT 3.1.1)
        0x02, // Connect Flags (Clean Session)
        0x00, 0x3C, // Keep Alive (60 seconds)
        0x00, 0x04, b'n', b'm', b'a', b'p', // Client ID: "nmap"
    ];

    stream.write_all(connect_packet).await.ok()?;

    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n >= 2 && (buf[0] >> 4) == 2 {
        let return_code = if n >= 4 { buf[3] } else { 255 };
        let version = match return_code {
            0 => Some("MQTT 3.1.1 (connection accepted)".to_string()),
            5 => Some("MQTT 3.1.1 (not authorized)".to_string()),
            _ => Some(format!("MQTT 3.1.1 (code: {})", return_code)),
        };
        return Some(ServiceInfo {
            name: "mqtt".to_string(),
            version,
            banner: None,
            tls_info: None,
        });
    }

    None
}

/// Telnet banner grab with negotiation handling.
async fn telnet_probe(addr: SocketAddr, timeout: Duration) -> Option<ServiceInfo> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    // Strip IAC negotiation sequences (0xFF cmd opt triples) before decoding text
    let mut text = String::new();
    let mut i = 0;
    while i < n {
        if buf[i] == 0xFF && i + 2 < n {
            i += 3;
        } else if buf[i].is_ascii_graphic() || buf[i] == b' ' || buf[i] == b'\n' {
            text.push(buf[i] as char);
            i += 1;
        } else {
            i += 1;
        }
    }

    let banner = text.trim().to_string();
    Some(ServiceInfo {
        name: "telnet".to_string(),
        version: if banner.is_empty() {
            None
        } else {
            Some(banner.clone())
        },
        banner: if banner.is_empty() {
            None
        } else {
            Some(banner)
        },
        tls_info: None,
    })
}

/// Redis INFO probe.
async fn redis_probe(addr: SocketAddr, timeout: Duration) -> Option<ServiceInfo> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    stream.write_all(b"INFO server\r\n").await.ok()?;

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    let response = String::from_utf8_lossy(&buf[..n]);

    if response.contains("redis_version:") {
        let version = response
            .lines()
            .find(|l| l.starts_with("redis_version:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|v| format!("Redis {}", v.trim()));

        return Some(ServiceInfo {
            name: "redis".to_string(),
            version,
            banner: Some(response.lines().take(5).collect::<Vec<_>>().join("\n")),
            tls_info: None,
        });
    }

    if response.contains("-NOAUTH") || response.contains("-ERR") {
        return Some(ServiceInfo {
            name: "redis".to_string(),
            version: Some("Redis (auth required)".to_string()),
            banner: Some(response.trim().to_string()),
            tls_info: None,
        });
    }

    None
}

/// SMB probe - negotiate protocol to extract server info.
async fn smb_probe(addr: SocketAddr, timeout: Duration) -> Option<ServiceInfo> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // SMB Negotiate Protocol Request (minimal, for SMB2)
    let negotiate: &[u8] = &[
        // NetBIOS Session header
        0x00, 0x00, 0x00, 0x2F, // length = 47
        // SMB2 header
        0xFE, b'S', b'M', b'B', // Protocol ID
        0x40, 0x00, // Structure Size (64)
        0x00, 0x00, // Credit Charge
        0x00, 0x00, 0x00, 0x00, // Status
        0x00, 0x00, // Command: Negotiate
        0x00, 0x00, // Credits
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Next Command
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
        0x00, 0x00, 0x00, 0x00, // Process ID
        0x00, 0x00, 0x00, 0x00, // Tree ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Signature
        // Negotiate body (minimal)
        0x24, 0x00, // Structure Size
        0x01, 0x00, // Dialect Count: 1
        0x00, 0x00, // Security Mode
        0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, // Capabilities
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Client GUID
        0x00, 0x00, 0x00, 0x00, // Negotiate Context Offset
        0x00, 0x00, // Negotiate Context Count
        0x00, 0x00, // Reserved2
        0x02, 0x02, // Dialect: SMB 2.002
    ];

    stream.write_all(negotiate).await.ok()?;

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n > 4 {
        if n > 8 && buf[4] == 0xFE && buf[5] == b'S' && buf[6] == b'M' && buf[7] == b'B' {
            return Some(ServiceInfo {
                name: "smb".to_string(),
                version: Some("SMB2".to_string()),
                banner: None,
                tls_info: None,
            });
        }
        if n > 8 && buf[4] == 0xFF && buf[5] == b'S' && buf[6] == b'M' && buf[7] == b'B' {
            return Some(ServiceInfo {
                name: "smb".to_string(),
                version: Some("SMB1".to_string()),
                banner: None,
                tls_info: None,
            });
        }
    }

    None
}

/// Send an HTTP GET request and parse the server header.
async fn http_probe(addr: SocketAddr, timeout: Duration) -> Option<ServiceInfo> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: nmapper/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        addr.ip()
    );

    stream.write_all(request.as_bytes()).await.ok()?;

    let mut buf = [0u8; 8192];
    let n = tokio::time::timeout(Duration::from_millis(3000), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    let response = String::from_utf8_lossy(&buf[..n]);

    if !response.starts_with("HTTP/") {
        return None;
    }

    let version = response
        .lines()
        .find(|line| line.to_lowercase().starts_with("server:"))
        .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()));

    Some(ServiceInfo {
        name: "http".to_string(),
        version,
        banner: Some(response.lines().next().unwrap_or_default().to_string()),
        tls_info: None,
    })
}

fn identify_from_banner(banner: &str, port: u16) -> Option<ServiceInfo> {
    let banner_lower = banner.to_lowercase();

    if banner_lower.starts_with("ssh-") {
        let version = banner.split_whitespace().next().map(String::from);
        return Some(ServiceInfo {
            name: "ssh".to_string(),
            version,
            banner: Some(banner.to_string()),
            tls_info: None,
        });
    }

    if banner_lower.starts_with("220") && (banner_lower.contains("ftp") || port == 21) {
        let version = extract_version_from_220(banner);
        return Some(ServiceInfo {
            name: "ftp".to_string(),
            version,
            banner: Some(banner.to_string()),
            tls_info: None,
        });
    }

    if banner_lower.starts_with("220")
        && (banner_lower.contains("smtp")
            || banner_lower.contains("mail")
            || port == 25
            || port == 587)
    {
        let version = extract_version_from_220(banner);
        return Some(ServiceInfo {
            name: "smtp".to_string(),
            version,
            banner: Some(banner.to_string()),
            tls_info: None,
        });
    }

    if banner_lower.starts_with("+ok") {
        return Some(ServiceInfo {
            name: "pop3".to_string(),
            version: None,
            banner: Some(banner.to_string()),
            tls_info: None,
        });
    }

    if banner_lower.contains("imap") || (banner_lower.starts_with("* ok") && port == 143) {
        return Some(ServiceInfo {
            name: "imap".to_string(),
            version: None,
            banner: Some(banner.to_string()),
            tls_info: None,
        });
    }

    if (port == 3306 || banner.len() > 4 && banner.as_bytes().get(4) == Some(&0x0a))
        && (banner_lower.contains("mysql") || banner_lower.contains("mariadb"))
    {
        return Some(ServiceInfo {
            name: "mysql".to_string(),
            version: extract_mysql_version(banner),
            banner: Some(banner.to_string()),
            tls_info: None,
        });
    }

    if banner_lower.contains("postgresql") || port == 5432 {
        return Some(ServiceInfo {
            name: "postgresql".to_string(),
            version: None,
            banner: Some(banner.to_string()),
            tls_info: None,
        });
    }

    if banner_lower.contains("redis")
        || banner_lower.starts_with("-err")
        || banner_lower.starts_with("-noauth")
    {
        return Some(ServiceInfo {
            name: "redis".to_string(),
            version: None,
            banner: Some(banner.to_string()),
            tls_info: None,
        });
    }

    if banner.starts_with("HTTP/") {
        let version = banner
            .lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string());
        return Some(ServiceInfo {
            name: "http".to_string(),
            version,
            banner: Some(banner.lines().next().unwrap_or_default().to_string()),
            tls_info: None,
        });
    }

    None
}

fn extract_version_from_220(banner: &str) -> Option<String> {
    let parts: Vec<&str> = banner.splitn(2, ' ').collect();
    if parts.len() > 1 {
        Some(parts[1].trim().to_string())
    } else {
        None
    }
}

fn extract_mysql_version(banner: &str) -> Option<String> {
    banner
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == '.')
        .collect::<String>()
        .split_whitespace()
        .find(|s| {
            s.contains('.')
                && s.chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
        })
        .map(String::from)
}

/// Map well-known port numbers to service names.
fn port_to_service_name(port: u16) -> &'static str {
    match port {
        7 => "echo",
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        69 => "tftp",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        500 => "isakmp",
        514 => "syslog",
        515 => "printer",
        520 => "rip",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1194 => "openvpn",
        1433 => "ms-sql",
        1434 => "ms-sql-m",
        1521 => "oracle",
        1723 => "pptp",
        2049 => "nfs",
        2181 => "zookeeper",
        2222 => "ssh-alt",
        3306 => "mysql",
        3389 => "rdp",
        3690 => "svn",
        4443 => "https-alt",
        5000 => "upnp",
        5060 => "sip",
        5432 => "postgresql",
        5900 | 5901 => "vnc",
        5984 => "couchdb",
        5985 | 5986 => "winrm",
        6000 => "x11",
        6379 => "redis",
        6667 => "irc",
        7001 | 7002 => "weblogic",
        8000 => "http-alt",
        8008 => "http-alt",
        8080 => "http-proxy",
        8081 => "http-alt",
        8443 => "https-alt",
        8834 => "nessus",
        8888 => "http-alt",
        9090 => "web-console",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        9418 => "git",
        9999 => "abyss",
        10000 => "webmin",
        27017 | 27018 => "mongodb",
        _ => "unknown",
    }
}
