use serde::Serialize;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub hosts: Vec<HostResult>,
    pub scan_info: ScanInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanInfo {
    pub start_time: String,
    pub duration_secs: f64,
    pub target_spec: String,
    pub scan_type: String,
    pub total_hosts_scanned: usize,
    pub hosts_up: usize,
    pub total_ports_scanned: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub status: HostStatus,
    pub ports: Vec<PortResult>,
    pub os: Option<OsFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

impl fmt::Display for HostStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostStatus::Up => write!(f, "up"),
            HostStatus::Down => write!(f, "down"),
            HostStatus::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsFingerprint {
    pub name: String,
    pub confidence: f32,
    pub details: OsDetails,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsDetails {
    pub ttl: u8,
    pub window_size: u16,
    pub df_bit: bool,
    pub tcp_options_order: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    Syn,
    Connect,
    Udp,
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanType::Syn => write!(f, "SYN"),
            ScanType::Connect => write!(f, "Connect"),
            ScanType::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod {
    Arp,
    Icmp,
    Tcp,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Both,
}

#[derive(Debug, Clone)]
pub struct TimingConfig {
    pub max_parallel: usize,
    pub delay_ms: u64,
    pub timeout_ms: u64,
    pub label: &'static str,
}

impl TimingConfig {
    pub fn from_template(t: u8) -> Self {
        match t {
            0 => TimingConfig {
                max_parallel: 1,
                delay_ms: 300,
                timeout_ms: 5000,
                label: "Paranoid",
            },
            1 => TimingConfig {
                max_parallel: 5,
                delay_ms: 100,
                timeout_ms: 3000,
                label: "Sneaky",
            },
            2 => TimingConfig {
                max_parallel: 20,
                delay_ms: 50,
                timeout_ms: 2000,
                label: "Polite",
            },
            3 => TimingConfig {
                max_parallel: 100,
                delay_ms: 10,
                timeout_ms: 1500,
                label: "Normal",
            },
            4 => TimingConfig {
                max_parallel: 500,
                delay_ms: 0,
                timeout_ms: 1000,
                label: "Aggressive",
            },
            _ => TimingConfig {
                max_parallel: 2000,
                delay_ms: 0,
                timeout_ms: 500,
                label: "Insane",
            },
        }
    }
}
