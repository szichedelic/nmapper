# nmapper

A network mapper written in Rust for host discovery, port scanning, service detection, and OS fingerprinting. Built for learning network security concepts.

## Features

- **Host Discovery**: ICMP ping sweep, ARP scanning (local subnet), TCP ping
- **Port Scanning**: TCP SYN (half-open), TCP connect, UDP
- **Service Detection**: Banner grabbing with protocol-specific probes (HTTP, SSH, FTP, SMTP, and more)
- **OS Fingerprinting**: TCP/IP stack analysis (TTL, window size, DF bit, TCP options)
- **Output**: Colored CLI table and/or JSON export
- **Rate Control**: Timing templates T0 (paranoid) through T5 (insane) with configurable concurrency

## Requirements

- Rust 1.70+
- macOS or Linux
- Root/sudo for SYN scanning, ARP discovery, and OS fingerprinting

## Build

```sh
cargo build --release
```

The binary will be at `target/release/nmapper`.

## Usage

```sh
# Scan a subnet with default settings (ICMP discovery + SYN scan on top 100 ports)
sudo nmapper 192.168.1.0/24

# TCP connect scan (no root required)
nmapper 10.0.0.1 -s connect -p 22,80,443

# Full scan with service detection and OS fingerprinting, output as table + JSON
sudo nmapper 192.168.1.0/24 -p common --sV -O -o both

# Scan a port range with JSON file export
sudo nmapper 10.0.0.1 -p 1-1024 --sV -o json --output-file results.json

# Fast scan with aggressive timing
sudo nmapper 192.168.1.0/24 -T5 -p 22,80,443
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --ports` | Port spec: `22,80,443`, `1-1024`, or `common` | `common` |
| `-s, --scan-type` | `syn`, `connect`, or `udp` | `syn` |
| `-d, --discovery` | `icmp`, `arp`, `tcp`, or `skip` | `icmp` |
| `-O, --os-detect` | Enable OS fingerprinting | off |
| `--sV` | Enable service/version detection | off |
| `-o, --output` | `table`, `json`, or `both` | `table` |
| `--output-file` | Write JSON to file | - |
| `-T, --timing` | Timing template 0-5 | `3` |
| `-v, --verbose` | Verbose output | off |
| `--max-parallel` | Max concurrent probes (overrides timing) | - |
| `--timeout` | Probe timeout in ms (overrides timing) | - |

## Timing Templates

| Template | Label | Max Parallel | Probe Delay | Timeout |
|----------|-------|-------------|-------------|---------|
| T0 | Paranoid | 1 | 300ms | 5000ms |
| T1 | Sneaky | 5 | 100ms | 3000ms |
| T2 | Polite | 20 | 50ms | 2000ms |
| T3 | Normal | 100 | 10ms | 1500ms |
| T4 | Aggressive | 500 | 0ms | 1000ms |
| T5 | Insane | 2000 | 0ms | 500ms |

## Scan Types

**SYN scan** (default, requires root): Sends TCP SYN packets and analyzes responses. Half-open scanning — never completes the three-way handshake. Sends RST after receiving SYN-ACK. Uses batch send-then-receive for speed.

**Connect scan** (no root required): Full TCP three-way handshake using async I/O. Fully parallel via tokio.

**UDP scan**: Sends empty datagrams. Ports that respond are open; ICMP unreachable means closed; no response means open or filtered.

## How It Works

1. **Discovery**: Identifies live hosts on the network using ICMP echo, ARP requests, or TCP connection attempts
2. **Port scanning**: Probes specified ports on each live host to determine open/closed/filtered state
3. **Service detection** (optional): Connects to open ports, grabs banners, and sends protocol-specific probes to identify running services and versions
4. **OS fingerprinting** (optional): Analyzes TCP/IP response characteristics (initial TTL, window size, TCP options) to estimate the target's operating system

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Only scan networks you own or have explicit permission to test.
