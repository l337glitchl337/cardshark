# Cardshark 🦈

A fast, lightweight ARP network scanner written in C for Linux. Cardshark discovers active hosts on your local network by sending ARP requests and listening for replies.

## Features

- **Fast Network Discovery** - Scans entire subnets quickly using raw ARP packets
- **Live Display** - Real-time updates as hosts are discovered
- **Thread-Safe** - Concurrent packet sending and receiving
- **Clean Shutdown** - Graceful cleanup on Ctrl+C
- **Minimal Dependencies** - Pure C with standard Linux libraries

## Requirements

- Linux operating system
- Root/sudo privileges (required for raw sockets)
- GCC compiler
- pthread library

## Installation

```bash
# Clone or download the source
git clone https://github.com/l337glitchl337/cardshark.git
cd cardshark

# Compile
gcc cardshark.c -o cardshark -lpthread

# Or use make
make cardshark

# Optional: Install to system
sudo cp cardshark /usr/local/bin/
```

## Usage

```bash
# Basic usage
sudo ./cardshark <interface>

# Examples
sudo ./cardshark eth0
sudo ./cardshark wlan0
```

### Output Example

```
5/256 nodes online:

192.168.1.1     [AA:BB:CC:DD:EE:FF]
192.168.1.100   [11:22:33:44:55:66]
192.168.1.101   [77:88:99:AA:BB:CC]
192.168.1.150   [DD:EE:FF:00:11:22]
192.168.1.200   [33:44:55:66:77:88]
```

Press `Ctrl+C` to stop scanning and exit cleanly.

## How It Works

1. **Interface Detection** - Retrieves IP address, netmask, and MAC address for specified interface
2. **Subnet Calculation** - Determines network range from CIDR notation
3. **ARP Scanning** - Broadcasts ARP requests to every IP in the subnet
4. **Reply Listening** - Separate thread captures and processes ARP replies
5. **Live Updates** - Displays discovered hosts in real-time

## Technical Details

- Uses raw `AF_PACKET` sockets for low-level network access
- Implements custom ARP packet construction
- Thread-safe linked list for host tracking
- Mutex-protected shared data structures
- Signal-safe shutdown with `volatile sig_atomic_t`

## Limitations

- **Linux only** - Uses Linux-specific raw socket APIs
- **IPv4 only** - Does not support IPv6
- **Local network only** - ARP only works on Layer 2 (same broadcast domain)
- **No root = no work** - Raw sockets require elevated privileges

## Security Considerations

⚠️ **Educational/Testing Use Only**

- Use only on networks you own or have explicit permission to scan
- ARP scanning can be detected by network monitoring tools
- Excessive scanning may trigger security alerts
- Running with root privileges carries inherent risks

## Troubleshooting

### "Error: Cardshark requires root privileges"
Run with `sudo`:
```bash
sudo ./cardshark eth0
```

### "Error: Interface not found"
Check available interfaces:
```bash
ip link show
# or
ifconfig
# or
ip addr
```

### No hosts discovered
- Verify you're on the correct interface
- Check firewall isn't blocking ARP
- Ensure interface has an IP address assigned
- Some devices may not respond to ARP requests

## Roadmap

- [ ] JSON/CSV export options
- [ ] Vendor lookup (MAC OUI database)
- [ ] Timestamps for first/last seen
- [ ] Configurable scan intervals
- [ ] IPv6 neighbor discovery support

## Project Structure

```
cardshark.c          # Single-file implementation (~450 lines)
├── Packet Structures (ARP, Ethernet)
├── Network Interface Detection
├── ARP Request Sender
├── ARP Reply Listener (threaded)
├── Host List Management
└── Signal Handling & Cleanup
```

## Contributing

This is a learning project, but suggestions and improvements are welcome!

## License

MIT License

Copyright (c) [2025] [Billy Hazwelwood]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Misc

Built as part of learning C network programming and security tooling.

## Acknowledgments

- Inspired by tools like `arp-scan` and `netdiscover`
- Part of the "Shark Suite" network security tools (Cardshark + Poolshark)

---

**Note**: This tool is for educational purposes and authorized network testing only.
