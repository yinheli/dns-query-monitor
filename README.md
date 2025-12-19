# DNS Query Monitor

[![build](https://github.com/yinheli/dns-query-monitor/actions/workflows/build.yml/badge.svg)](https://github.com/yinheli/dns-query-monitor/actions/workflows/build.yml)

Real-time DNS query monitoring tool with Terminal User Interface (TUI).

## Features

- Monitor DNS queries across all network interfaces or specific ones
- Real-time display with interactive TUI
- Sort by time, count, or domain name
- Filter queries by domain pattern
- Support for IPv4 and IPv6

## Installation

### Prerequisites

- Linux system
- libpcap library
- Root/sudo privileges (for packet capture)

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel

# Arch Linux
sudo pacman -S libpcap
```

### Docker (Recommended)

```bash
# Pull from Docker Hub
docker pull yinheli/dns-query-monitor

# Run with host network mode
# --net=host: Share host's network namespace to access all network interfaces
# --cap-add=NET_ADMIN: Grant network administration capabilities for packet capture
docker run --rm -it --cap-add=NET_ADMIN --net=host \
  yinheli/dns-query-monitor
```

### Install with Cargo

```bash
# From crates.io
cargo install dns-query-monitor

# From git repository
cargo install --git https://github.com/yinheli/dns-query-monitor

# Or clone and install locally
git clone https://github.com/yinheli/dns-query-monitor
cd dns-query-monitor
cargo install --path .
```

### Build from Source

```bash
# Clone repository
git clone https://github.com/yinheli/dns-query-monitor
cd dns-query-monitor

# Build
cargo build --release

# Binary location
./target/release/dns-query-monitor
```

## Usage

### Docker

```bash
# Auto-select interface (default)
docker run --rm -it --cap-add=NET_ADMIN --net=host \
  yinheli/dns-query-monitor

# List available network interfaces
docker run --rm -it --cap-add=NET_ADMIN --net=host \
  yinheli/dns-query-monitor --list-interfaces

# Monitor specific interface
docker run --rm -it --cap-add=NET_ADMIN --net=host \
  yinheli/dns-query-monitor -i eth0

# Filter by domain
docker run --rm -it --cap-add=NET_ADMIN --net=host \
  yinheli/dns-query-monitor -f google
```

### Binary

```bash
# List available network interfaces
sudo dns-query-monitor --list-interfaces

# Auto-select interface (default)
sudo dns-query-monitor

# Monitor specific interface
sudo dns-query-monitor -i eth0

# Filter by domain
sudo dns-query-monitor -f google
```

### Options

```
-i, --interface <INTERFACE>  Network interface (auto-detect if not specified)
-f, --filter <FILTER>        Filter domain names
-l, --log-level <LEVEL>      Log level [default: info]
    --list-interfaces        List available network interfaces
-h, --help                   Show help
```

### Keyboard Controls

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit program |
| `Esc` | Exit filter mode |
| `/` | Enter filter mode |
| `s` | Toggle sort (Time → Count → Domain) |
| `↑` `↓` / `j` `k` | Navigate |
| `PgUp` / `PgDn` | Page up/down |
| `Home` / `End` | Jump to top/bottom |

> **Tip**: You can select text with your mouse and copy with `Ctrl+Shift+C` (Linux) or `Cmd+C` (macOS) directly from the terminal.

## Display

```
┌─ DNS Query Monitor | Domains: 42 | Queries: 156 ──────────────────────┐
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
┌─ DNS Queries [Sort: Time ↓] ──────────────────────────────────────────┐
│ Domain              │ IP Address    │ Last Query          │ Count     │
│ example.com         │ 1.1.1.1       │ 2024-06-01 12:00:00 │ 5         │
│ github.com          │ 8.8.8.8       │ 2024-06-01 11:59:45 │ 12        │
└───────────────────────────────────────────────────────────────────────┘
```

## Troubleshooting

**Permission denied**: Run with `sudo`

**No queries captured**:
- Check network interface with `ip link show`
- Verify DNS traffic with `dig example.com`
- Try debug mode: `-l debug`

## Notes

- Only monitors unencrypted DNS (UDP port 53)
- Does not support DoH (DNS over HTTPS) or DoT (DNS over TLS)
- IP addresses limited to 2 per domain in display (e.g., `ip1, ip2, ... (+3)`)

## License

MIT
