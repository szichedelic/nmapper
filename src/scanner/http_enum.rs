use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::models::{HttpPath, HttpPathResult};

const TIMEOUT_MS: u64 = 3000;

const WORDLIST: &[&str] = &[
    "/", "/admin", "/login", "/api", "/api/v1", "/.git/HEAD",
    "/.env", "/wp-admin", "/wp-login.php", "/robots.txt",
    "/sitemap.xml", "/.well-known/security.txt", "/server-status",
    "/server-info", "/phpmyadmin", "/console", "/debug",
    "/actuator", "/actuator/health", "/swagger-ui.html",
    "/api-docs", "/graphql", "/.htaccess", "/backup",
    "/config", "/dashboard", "/manager", "/status",
    "/health", "/healthz", "/metrics", "/info",
    "/.git/config", "/.svn/entries", "/.DS_Store",
    "/wp-content", "/wp-includes", "/xmlrpc.php",
    "/cgi-bin/", "/test", "/dev", "/staging",
    "/old", "/new", "/temp", "/tmp",
];

pub fn http_enumerate(target: IpAddr, port: u16, verbose: bool) -> HttpPathResult {
    let mut paths = Vec::new();

    for &path in WORDLIST {
        match probe_path(target, port, path) {
            Some(result) => {
                if matches!(result.status, 200 | 301 | 302 | 307 | 308 | 401 | 403 | 405 | 500) {
                    if verbose {
                        eprintln!(
                            "  [+] {target}:{port}{path} -> {} ({})",
                            result.status,
                            result.content_length.map(|l| format!("{l}B")).unwrap_or_default()
                        );
                    }
                    paths.push(result);
                }
            }
            None => continue,
        }
    }

    HttpPathResult { port, paths }
}

fn probe_path(target: IpAddr, port: u16, path: &str) -> Option<HttpPath> {
    let addr = SocketAddr::new(target, port);
    let timeout = Duration::from_millis(TIMEOUT_MS);

    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;

    let host = if port == 80 || port == 443 {
        target.to_string()
    } else {
        format!("{target}:{port}")
    };

    let request = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nmapper/0.3.0\r\nConnection: close\r\n\r\n"
    );

    stream.write_all(request.as_bytes()).ok()?;

    let reader = BufReader::new(&stream);
    let mut lines = reader.lines();

    let status_line = lines.next()?.ok()?;
    let parts: Vec<&str> = status_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let status: u16 = parts[1].parse().ok()?;

    let mut content_length = None;
    let mut redirect = None;

    for line in lines {
        match line {
            Ok(l) => {
                let trimmed = l.trim().to_string();
                if trimmed.is_empty() {
                    break;
                }
                let lower = trimmed.to_lowercase();
                if lower.starts_with("content-length:") {
                    content_length = trimmed[15..].trim().parse().ok();
                } else if lower.starts_with("location:") {
                    redirect = Some(trimmed[9..].trim().to_string());
                }
            }
            Err(_) => break,
        }
    }

    Some(HttpPath {
        path: path.to_string(),
        status,
        content_length,
        redirect,
    })
}
