use std::path::PathBuf;

use anyhow::{Context, Result};
use colored::Colorize;
use rusqlite::{params, Connection};

use crate::models::{HostStatus, PortState, ScanResult};

fn db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dir = PathBuf::from(home).join(".nmapper");
    std::fs::create_dir_all(&dir).ok();
    dir.join("scan_history.db")
}

fn open_db() -> Result<Connection> {
    let path = db_path();
    let conn = Connection::open(&path)
        .with_context(|| format!("Failed to open database at {}", path.display()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            duration_secs REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            ip TEXT NOT NULL,
            hostname TEXT,
            mac_address TEXT,
            vendor TEXT,
            status TEXT NOT NULL,
            os_name TEXT,
            os_confidence REAL
        );
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id),
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service_name TEXT,
            service_version TEXT
        );",
    )
    .context("Failed to initialize database schema")?;

    Ok(conn)
}

/// Save scan results to the local database.
pub fn save_scan(result: &ScanResult) -> Result<()> {
    let conn = open_db()?;

    conn.execute(
        "INSERT INTO scans (target, scan_type, timestamp, duration_secs) VALUES (?1, ?2, ?3, ?4)",
        params![
            result.scan_info.target_spec,
            result.scan_info.scan_type,
            result.scan_info.start_time,
            result.scan_info.duration_secs,
        ],
    )?;
    let scan_id = conn.last_insert_rowid();

    for host in &result.hosts {
        conn.execute(
            "INSERT INTO hosts (scan_id, ip, hostname, mac_address, vendor, status, os_name, os_confidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                scan_id,
                host.ip.to_string(),
                host.hostname,
                host.mac_address.map(|m| m.to_string()),
                host.vendor,
                host.status.to_string(),
                host.os.as_ref().map(|o| o.name.clone()),
                host.os.as_ref().map(|o| o.confidence),
            ],
        )?;
        let host_id = conn.last_insert_rowid();

        for port in &host.ports {
            conn.execute(
                "INSERT INTO ports (host_id, port, protocol, state, service_name, service_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    host_id,
                    port.port as i64,
                    port.protocol.to_string(),
                    port.state.to_string(),
                    port.service.as_ref().map(|s| s.name.clone()),
                    port.service.as_ref().and_then(|s| s.version.clone()),
                ],
            )?;
        }
    }

    eprintln!("[*] Scan saved to database (scan #{})", scan_id);
    Ok(())
}

/// Compare current scan against the most recent previous scan for the same target.
pub fn diff_scan(result: &ScanResult) -> Result<()> {
    let conn = open_db()?;

    let prev_scan_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM scans WHERE target = ?1 ORDER BY id DESC LIMIT 1",
            params![result.scan_info.target_spec],
            |row| row.get(0),
        )
        .ok();

    let prev_scan_id = match prev_scan_id {
        Some(id) => id,
        None => {
            eprintln!(
                "{}",
                "[*] No previous scan found for this target. Saving current scan as baseline."
                    .dimmed()
            );
            save_scan(result)?;
            return Ok(());
        }
    };

    let mut stmt = conn.prepare(
        "SELECT ip, hostname, status, os_name FROM hosts WHERE scan_id = ?1",
    )?;
    let prev_hosts: Vec<(String, Option<String>, String, Option<String>)> = stmt
        .query_map(params![prev_scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    let mut port_stmt = conn.prepare(
        "SELECT p.port, p.protocol, p.state, p.service_name
         FROM ports p JOIN hosts h ON p.host_id = h.id
         WHERE h.scan_id = ?1 AND h.ip = ?2",
    )?;

    println!();
    println!(
        "{}",
        "nmapper diff — comparing against previous scan".bold()
    );
    println!("{}", "─".repeat(60));

    let mut changes = 0;

    for host in &result.hosts {
        let ip_str = host.ip.to_string();
        let prev = prev_hosts.iter().find(|(ip, _, _, _)| ip == &ip_str);

        match prev {
            None => {
                if host.status == HostStatus::Up {
                    println!(
                        "  {} {} {}",
                        "+".green().bold(),
                        "NEW DEVICE:".green().bold(),
                        ip_str.cyan()
                    );
                    if let Some(ref vendor) = host.vendor {
                        println!("    Vendor: {}", vendor.yellow());
                    }
                    if let Some(ref hostname) = host.hostname {
                        println!("    Hostname: {hostname}");
                    }
                    let open: Vec<_> = host
                        .ports
                        .iter()
                        .filter(|p| p.state == PortState::Open)
                        .map(|p| format!("{}", p.port))
                        .collect();
                    if !open.is_empty() {
                        println!("    Open ports: {}", open.join(", "));
                    }
                    changes += 1;
                }
            }
            Some((_, _, prev_status, _)) => {
                if prev_status == "down" && host.status == HostStatus::Up {
                    println!(
                        "  {} {} {} (was down, now up)",
                        "+".green().bold(),
                        "CAME ONLINE:".green().bold(),
                        ip_str.cyan()
                    );
                    changes += 1;
                } else if prev_status == "up" && host.status != HostStatus::Up {
                    println!(
                        "  {} {} {} (was up, now {})",
                        "-".red().bold(),
                        "WENT OFFLINE:".red().bold(),
                        ip_str.cyan(),
                        host.status
                    );
                    changes += 1;
                }

                if host.status == HostStatus::Up {
                    let prev_ports: Vec<(i64, String, String, Option<String>)> = port_stmt
                        .query_map(params![prev_scan_id, ip_str.clone()], |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, Option<String>>(3)?,
                            ))
                        })
                        .ok()
                        .map(|rows| rows.filter_map(|r| r.ok()).collect())
                        .unwrap_or_default();

                    for port in &host.ports {
                        if port.state != PortState::Open {
                            continue;
                        }
                        let prev_port = prev_ports
                            .iter()
                            .find(|(p, proto, _, _)| {
                                *p == port.port as i64 && proto == &port.protocol.to_string()
                            });
                        match prev_port {
                            None => {
                                let svc = port
                                    .service
                                    .as_ref()
                                    .map(|s| s.name.as_str())
                                    .unwrap_or("unknown");
                                println!(
                                    "  {} {}: port {}/{} opened ({})",
                                    "+".green(),
                                    ip_str.cyan(),
                                    port.port,
                                    port.protocol,
                                    svc
                                );
                                changes += 1;
                            }
                            Some((_, _, prev_state, _)) if prev_state != "open" => {
                                println!(
                                    "  {} {}: port {}/{} changed {} -> {}",
                                    "~".yellow(),
                                    ip_str.cyan(),
                                    port.port,
                                    port.protocol,
                                    prev_state,
                                    port.state
                                );
                                changes += 1;
                            }
                            _ => {}
                        }
                    }

                    for (prev_port, prev_proto, prev_state, prev_svc) in &prev_ports {
                        if prev_state != "open" {
                            continue;
                        }
                        let still_open = host.ports.iter().any(|p| {
                            p.port as i64 == *prev_port
                                && p.protocol.to_string() == *prev_proto
                                && p.state == PortState::Open
                        });
                        if !still_open {
                            let svc = prev_svc.as_deref().unwrap_or("unknown");
                            println!(
                                "  {} {}: port {}/{} closed (was {} {})",
                                "-".red(),
                                ip_str.cyan(),
                                prev_port,
                                prev_proto,
                                "open",
                                svc
                            );
                            changes += 1;
                        }
                    }
                }
            }
        }
    }

    for (prev_ip, _, prev_status, _) in &prev_hosts {
        if prev_status != "up" {
            continue;
        }
        let still_present = result
            .hosts
            .iter()
            .any(|h| h.ip.to_string() == *prev_ip && h.status == HostStatus::Up);
        if !still_present {
            println!(
                "  {} {} {} (no longer responding)",
                "-".red().bold(),
                "REMOVED:".red().bold(),
                prev_ip.cyan()
            );
            changes += 1;
        }
    }

    println!("{}", "─".repeat(60));
    if changes == 0 {
        println!("{}", "No changes detected since last scan.".dimmed());
    } else {
        println!(
            "{}",
            format!("{changes} change(s) detected since last scan.").bold()
        );
    }
    println!();

    save_scan(result)?;

    Ok(())
}
