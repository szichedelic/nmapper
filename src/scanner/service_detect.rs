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
    // First try: connect and grab the banner (many services send a banner immediately)
    let banner = grab_banner(target, port, timeout).await;

    // If we got a banner, try to identify the service from it
    if let Some(ref banner_text) = banner {
        if let Some(service) = identify_from_banner(banner_text, port) {
            return Some(service);
        }
    }

    // Second try: send protocol-specific probes
    if let Some(service) = protocol_probe(target, port, timeout).await {
        return Some(service);
    }

    // Fallback: identify by port number alone
    Some(ServiceInfo {
        name: port_to_service_name(port).to_string(),
        version: None,
        banner,
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

    // For any port, try HTTP as a last resort (many services run on non-standard ports)
    if let Some(service) = http_probe(addr, timeout).await {
        return Some(service);
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

    // Extract Server header
    let version = response
        .lines()
        .find(|line| line.to_lowercase().starts_with("server:"))
        .and_then(|line| line.split_once(':').map(|(_, v)| v.trim().to_string()));

    Some(ServiceInfo {
        name: "http".to_string(),
        version,
        banner: Some(response.lines().next().unwrap_or_default().to_string()),
    })
}

fn identify_from_banner(banner: &str, port: u16) -> Option<ServiceInfo> {
    let banner_lower = banner.to_lowercase();

    // SSH
    if banner_lower.starts_with("ssh-") {
        let version = banner.split_whitespace().next().map(String::from);
        return Some(ServiceInfo {
            name: "ssh".to_string(),
            version,
            banner: Some(banner.to_string()),
        });
    }

    // FTP
    if banner_lower.starts_with("220") && (banner_lower.contains("ftp") || port == 21) {
        let version = extract_version_from_220(banner);
        return Some(ServiceInfo {
            name: "ftp".to_string(),
            version,
            banner: Some(banner.to_string()),
        });
    }

    // SMTP
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
        });
    }

    // POP3
    if banner_lower.starts_with("+ok") {
        return Some(ServiceInfo {
            name: "pop3".to_string(),
            version: None,
            banner: Some(banner.to_string()),
        });
    }

    // IMAP
    if banner_lower.contains("imap") || (banner_lower.starts_with("* ok") && port == 143) {
        return Some(ServiceInfo {
            name: "imap".to_string(),
            version: None,
            banner: Some(banner.to_string()),
        });
    }

    // MySQL
    if (port == 3306 || banner.len() > 4 && banner.as_bytes().get(4) == Some(&0x0a))
        && (banner_lower.contains("mysql") || banner_lower.contains("mariadb"))
    {
        return Some(ServiceInfo {
            name: "mysql".to_string(),
            version: extract_mysql_version(banner),
            banner: Some(banner.to_string()),
        });
    }

    // PostgreSQL
    if banner_lower.contains("postgresql") || port == 5432 {
        return Some(ServiceInfo {
            name: "postgresql".to_string(),
            version: None,
            banner: Some(banner.to_string()),
        });
    }

    // Redis
    if banner_lower.contains("redis")
        || banner_lower.starts_with("-err")
        || banner_lower.starts_with("-noauth")
    {
        return Some(ServiceInfo {
            name: "redis".to_string(),
            version: None,
            banner: Some(banner.to_string()),
        });
    }

    // HTTP response
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
        });
    }

    None
}

fn extract_version_from_220(banner: &str) -> Option<String> {
    // "220 server FTPd 1.2.3 Ready" → "FTPd 1.2.3"
    let parts: Vec<&str> = banner.splitn(2, ' ').collect();
    if parts.len() > 1 {
        Some(parts[1].trim().to_string())
    } else {
        None
    }
}

fn extract_mysql_version(banner: &str) -> Option<String> {
    // MySQL banner often has version string after the first few bytes
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
