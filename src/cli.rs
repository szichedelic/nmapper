use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "nmapper",
    about = "Network mapper for host discovery, port scanning, and vulnerability assessment",
    version,
    after_help = "EXAMPLES:\n  \
        sudo nmapper 192.168.1.0/24                    # Discover hosts on subnet\n  \
        sudo nmapper 10.0.0.1 -p 1-1024 -sV           # Scan ports with service detection\n  \
        sudo nmapper 192.168.1.0/24 -p common -O -o both  # Full scan with OS detection\n  \
        nmapper 10.0.0.1 -s connect -p 22,80,443       # Unprivileged TCP connect scan"
)]
pub struct Cli {
    /// Target IP, hostname, or CIDR range (e.g., 192.168.1.0/24)
    pub targets: String,

    /// Port specification: "22,80,443", "1-1024", or "common" (top 100)
    #[arg(short, long, default_value = "common")]
    pub ports: String,

    /// Scan type: syn, connect, udp, fin, null, xmas
    #[arg(short = 's', long = "scan-type", default_value = "syn")]
    pub scan_type: String,

    /// Discovery method: arp, icmp, tcp, skip
    #[arg(short = 'd', long = "discovery", default_value = "icmp")]
    pub discovery: String,

    /// Enable OS fingerprinting
    #[arg(short = 'O', long = "os-detect")]
    pub os_detect: bool,

    /// Enable service/version detection
    #[arg(long = "sV")]
    pub service_version: bool,

    /// Enable mDNS/Bonjour device discovery
    #[arg(long = "mdns")]
    pub mdns: bool,

    /// Enable SSDP/UPnP device discovery
    #[arg(long = "ssdp")]
    pub ssdp: bool,

    /// Output format: table, json, html, both
    #[arg(short = 'o', long = "output", default_value = "table")]
    pub output: String,

    /// Write JSON output to file
    #[arg(long = "output-file")]
    pub output_file: Option<String>,

    /// Timing template 0-5 (0=paranoid, 3=normal, 5=insane)
    #[arg(short = 'T', long = "timing", default_value = "3")]
    pub timing: u8,

    /// Compare results against previous scan (diff mode)
    #[arg(long = "diff")]
    pub diff: bool,

    /// Check for default credentials and open service warnings
    #[arg(long = "vuln-check")]
    pub vuln_check: bool,

    /// Passive discovery mode (listen only, no probes sent)
    #[arg(long = "passive")]
    pub passive: bool,

    /// Duration in seconds for passive discovery
    #[arg(long = "duration", default_value = "30")]
    pub duration: u64,

    /// Continuous scanning mode with alerts on changes
    #[arg(long = "watch")]
    pub watch: bool,

    /// Interval in seconds between watch mode scans
    #[arg(long = "interval", default_value = "300")]
    pub interval: u64,

    /// Randomize TCP window size and TTL per probe (OS fingerprint evasion)
    #[arg(long = "randomize-tcp")]
    pub randomize_tcp: bool,

    /// Decoy IP addresses to mix into raw scan probes (e.g., 10.0.0.1,10.0.0.2)
    #[arg(long = "decoys", value_delimiter = ',')]
    pub decoys: Vec<String>,

    /// Fragment IP packets to evade deep packet inspection (raw scans only)
    #[arg(long = "fragment")]
    pub fragment: bool,

    /// Interleave scanning across hosts (scan port X on all hosts, then port Y)
    #[arg(long = "interleave")]
    pub interleave: bool,

    /// Increase verbosity
    #[arg(short, long)]
    pub verbose: bool,

    /// Max concurrent probes (overrides timing template)
    #[arg(long = "max-parallel")]
    pub max_parallel: Option<usize>,

    /// Probe timeout in ms (overrides timing template)
    #[arg(long = "timeout")]
    pub timeout: Option<u64>,
}
