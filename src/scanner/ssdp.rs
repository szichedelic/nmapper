use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SsdpDevice {
    pub ip: IpAddr,
    pub server: Option<String>,
    pub location: Option<String>,
    pub device_type: Option<String>,
    pub friendly_name: Option<String>,
}

/// Discover devices via SSDP M-SEARCH on the local network.
pub fn ssdp_discover(duration_secs: u64, verbose: bool) -> Vec<SsdpDevice> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            if verbose {
                eprintln!("  [!] SSDP: failed to bind socket: {e}");
            }
            return Vec::new();
        }
    };

    let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));

    let multicast_addr = Ipv4Addr::new(239, 255, 255, 250);
    let _ = socket.join_multicast_v4(&multicast_addr, &Ipv4Addr::UNSPECIFIED);

    let ssdp_target: SocketAddr = "239.255.255.250:1900".parse().unwrap();

    let search_targets = [
        "ssdp:all",
        "upnp:rootdevice",
        "urn:schemas-upnp-org:device:MediaRenderer:1",
        "urn:schemas-upnp-org:device:MediaServer:1",
    ];

    for st in &search_targets {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 3\r\n\
             ST: {st}\r\n\
             \r\n"
        );
        let _ = socket.send_to(msg.as_bytes(), ssdp_target);
    }

    let mut devices: HashMap<IpAddr, SsdpDevice> = HashMap::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(duration_secs);
    let mut buf = [0u8; 4096];

    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let response = String::from_utf8_lossy(&buf[..len]);
                let ip = src.ip();

                if ip == IpAddr::V4(Ipv4Addr::LOCALHOST) {
                    continue;
                }

                let server = extract_header(&response, "SERVER");
                let location = extract_header(&response, "LOCATION");
                let st = extract_header(&response, "ST");

                let device = devices.entry(ip).or_insert_with(|| SsdpDevice {
                    ip,
                    server: None,
                    location: None,
                    device_type: None,
                    friendly_name: None,
                });

                if device.server.is_none() {
                    device.server = server;
                }
                if device.location.is_none() {
                    device.location = location.clone();
                }
                if device.device_type.is_none() {
                    device.device_type = st;
                }

                if verbose {
                    eprintln!("  [+] SSDP: {} ({})", ip, device.server.as_deref().unwrap_or("?"));
                }

                if device.friendly_name.is_none() {
                    if let Some(ref loc) = location {
                        if let Some(name) = fetch_friendly_name(loc) {
                            device.friendly_name = Some(name);
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    let _ = socket.leave_multicast_v4(&multicast_addr, &Ipv4Addr::UNSPECIFIED);

    devices.into_values().collect()
}

fn extract_header(response: &str, header: &str) -> Option<String> {
    let header_lower = header.to_lowercase();
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with(&header_lower) {
            if let Some(pos) = line.find(':') {
                let value = line[pos + 1..].trim().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Fetch UPnP device description XML and extract the friendlyName.
fn fetch_friendly_name(location_url: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let url = location_url.strip_prefix("http://")?;
    let (host_port, path) = if let Some(pos) = url.find('/') {
        (&url[..pos], &url[pos..])
    } else {
        (url, "/")
    };

    let stream = TcpStream::connect_timeout(
        &host_port.parse::<SocketAddr>().ok()?,
        Duration::from_millis(1000),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(1000))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(500))).ok()?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n"
    );
    (&stream).write_all(request.as_bytes()).ok()?;

    let mut response = String::new();
    let mut buf = [0u8; 16384];
    let mut total = 0;
    loop {
        match (&stream).read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= buf.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    response.push_str(&String::from_utf8_lossy(&buf[..total]));

    extract_xml_tag(&response, "friendlyName")
        .or_else(|| extract_xml_tag(&response, "modelName"))
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}
