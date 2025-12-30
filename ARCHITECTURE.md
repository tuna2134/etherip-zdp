# EtherIP-ZDP Architecture

## Overview

EtherIP-ZDP is a high-performance implementation of RFC 3378 (EtherIP) using Rust and eBPF/XDP technology. It creates Layer 2 tunnels over IPv4 or IPv6 networks.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Space                              │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  etherip-zdp (main.rs)                                   │   │
│  │  - Parse command-line arguments                          │   │
│  │  - Configure network interfaces                          │   │
│  │  - Load eBPF programs                                    │   │
│  │  - Populate eBPF maps (MAC, IP, DevMap)                  │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────┘
                             │ Aya-rs API
                             │
┌────────────────────────────┼────────────────────────────────────┐
│                         Kernel Space                            │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐   │
│  │  XDP Programs (eBPF)                                    │   │
│  │  ┌────────────────────┐  ┌────────────────────┐        │   │
│  │  │  encap             │  │  decap             │        │   │
│  │  │  - Detect IP ver   │  │  - Detect IP ver   │        │   │
│  │  │  - Add headers     │  │  - Validate proto  │        │   │
│  │  │  - Route to tunnel │  │  - Strip headers   │        │   │
│  │  └────────────────────┘  └────────────────────┘        │   │
│  │                                                          │   │
│  │  ┌────────────────────────────────────────────────┐    │   │
│  │  │  eBPF Maps                                     │    │   │
│  │  │  - MACADDRESS: Source/dest MAC addresses       │    │   │
│  │  │  - IPADDRESS: Source/dest IP addresses (16B)   │    │   │
│  │  │  - IP_VERSION: IPv4 (0) or IPv6 (1)           │    │   │
│  │  │  - DEV_MAP: Network device redirection map     │    │   │
│  │  └────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐   │
│  │  Network Interfaces                                     │   │
│  │  - Physical/Virtual NICs                                │   │
│  │  - XDP hooks attached                                   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Packet Flow

### Encapsulation (Outbound)

```
1. Packet arrives at device interface
2. XDP hook triggers encap program
3. Program checks IP_VERSION map
4. Adds space for headers:
   - IPv4: Eth(14) + IPv4(20) + EtherIP(2) = 36 bytes
   - IPv6: Eth(14) + IPv6(40) + EtherIP(2) = 56 bytes
5. Fills in outer Ethernet header
6. Fills in outer IP header (IPv4 or IPv6)
7. Fills in EtherIP header (version=3)
8. Redirects to tunnel interface via DEV_MAP
```

### Decapsulation (Inbound)

```
1. Packet arrives at tunnel interface
2. XDP hook triggers decap program
3. Program checks Ethernet type (IPv4 or IPv6)
4. Validates IP protocol is EtherIP (97)
5. Validates EtherIP version is 3
6. Strips outer headers:
   - IPv4: Eth(14) + IPv4(20) + EtherIP(2) = 36 bytes
   - IPv6: Eth(14) + IPv6(40) + EtherIP(2) = 56 bytes
7. Redirects inner frame to destination interface via DEV_MAP
```

## Components

### 1. Userspace Program (etherip-zdp)

**Responsibilities:**
- Parse command-line arguments (source/dest addresses, device)
- Detect IP version (IPv4 or IPv6) from address format
- Resolve MAC addresses via ARP/NDP
- Load and attach XDP programs
- Configure eBPF maps with tunnel parameters
- Signal handling for graceful shutdown

**Key Files:**
- `etherip-zdp/src/main.rs` - Main program logic
- `etherip-zdp/src/mac.rs` - MAC address resolution (ARP/NDP)

### 2. eBPF Programs (etherip-zdp-ebpf)

**Responsibilities:**
- Fast-path packet processing in kernel
- Zero-copy packet modification
- Header manipulation (add/remove)
- Packet validation
- Device redirection

**Key Files:**
- `etherip-zdp-ebpf/src/main.rs` - XDP programs

**Maps:**
- `MACADDRESS`: HashMap<u32, [u8; 6]> - MAC addresses
  - Key 0: Source MAC
  - Key 1: Destination MAC
  
- `IPADDRESS`: HashMap<u32, [u8; 16]> - IP addresses
  - Key 0: Source IP (16 bytes, IPv4 padded)
  - Key 1: Destination IP (16 bytes, IPv4 padded)
  
- `IP_VERSION`: HashMap<u32, u8> - IP version flag
  - Key 0: 0=IPv4, 1=IPv6
  
- `DEV_MAP`: DevMap - Device redirection
  - Index 0: Tunnel endpoint interface
  - Index 1: Bridged/destination interface

### 3. Common Library (etherip-zdp-common)

**Responsibilities:**
- Shared types and constants
- Common utilities between userspace and eBPF

## Data Structures

### EtherIP Header (RFC 3378)

```rust
#[repr(C)]
struct EtherIPHdr {
    version: u8,   // Version (4 bits) + reserved (4 bits)
    reserved: u8,  // Reserved (8 bits)
}
// Total: 2 bytes
// Version field: 0x30 (version 3)
// Reserved: 0x00
```

### Packet Format (IPv4)

```
┌───────────────────────────────────────┐
│  Outer Ethernet Header (14 bytes)    │
├───────────────────────────────────────┤
│  IPv4 Header (20 bytes)               │
│  - Protocol: 97 (EtherIP)             │
├───────────────────────────────────────┤
│  EtherIP Header (2 bytes)             │
│  - Version: 3                         │
├───────────────────────────────────────┤
│  Inner Ethernet Frame                 │
│  ┌─────────────────────────────────┐  │
│  │ Ethernet Header (14 bytes)      │  │
│  ├─────────────────────────────────┤  │
│  │ Payload                         │  │
│  └─────────────────────────────────┘  │
└───────────────────────────────────────┘
```

### Packet Format (IPv6)

```
┌───────────────────────────────────────┐
│  Outer Ethernet Header (14 bytes)    │
├───────────────────────────────────────┤
│  IPv6 Header (40 bytes)               │
│  - Next Header: 97 (EtherIP)          │
├───────────────────────────────────────┤
│  EtherIP Header (2 bytes)             │
│  - Version: 3                         │
├───────────────────────────────────────┤
│  Inner Ethernet Frame                 │
│  ┌─────────────────────────────────┐  │
│  │ Ethernet Header (14 bytes)      │  │
│  ├─────────────────────────────────┤  │
│  │ Payload                         │  │
│  └─────────────────────────────────┘  │
└───────────────────────────────────────┘
```

## Performance Characteristics

### XDP (eXpress Data Path)

- **Zero-copy**: Packets modified in-place
- **Kernel bypass**: Processes before network stack
- **High throughput**: Millions of packets per second
- **Low latency**: Microsecond-level processing

### Overhead

| Protocol | Overhead | MTU Impact |
|----------|----------|------------|
| IPv4     | 36 bytes | 1500 → 1464 |
| IPv6     | 56 bytes | 1500 → 1444 |

## Router Traversal

The implementation supports routing through multiple routers:

1. **TTL/Hop Limit**: Set to 255 for maximum hops
2. **Standard Routing**: Uses normal IP routing tables
3. **NAT Compatibility**: Works through NAT gateways
4. **No Special Config**: Routers treat as regular IP packets

## Fragmentation Handling

### Strategy

- **IP Layer Fragmentation**: Handled by kernel IP stack
- **Transparent**: XDP sees reassembled packets
- **MTU Awareness**: Accounts for header overhead
- **IPv4**: Uses standard IP fragmentation
- **IPv6**: Uses IPv6 fragmentation extension header

### Notes

- Large frames are fragmented at IP layer if needed
- Reassembly happens before XDP hook on receive side
- Path MTU Discovery can be enabled if needed

## Security Considerations

Per RFC 3378:

- **No Built-in Security**: EtherIP has no encryption
- **Recommendation**: Use IPsec for secure tunnels
- **Authentication**: Should be handled at IP layer
- **Encryption**: Should be handled at IP layer

### Mitigation Options

1. IPsec tunnel mode over EtherIP
2. VPN solutions at IP layer
3. Network segmentation
4. Firewall rules for EtherIP protocol (97)

## Build System

```
┌─────────────────────────────────────────┐
│  Cargo Workspace                        │
│  ├── etherip-zdp (userspace)            │
│  │   └── build.rs (builds eBPF)         │
│  ├── etherip-zdp-ebpf (eBPF programs)   │
│  │   └── build.rs (compile to BPF)      │
│  └── etherip-zdp-common (shared)        │
└─────────────────────────────────────────┘
```

- **Build Script**: Automatically compiles eBPF programs
- **eBPF Compilation**: Uses bpf-linker and nightly Rust
- **Embedding**: eBPF bytecode embedded in userspace binary
- **Cross-compilation**: Supports musl targets

## Dependencies

### Userspace
- `aya`: eBPF library for Rust
- `tokio`: Async runtime
- `rtnetlink`: Netlink communication
- `pnet`: Packet manipulation (ARP/NDP)
- `clap`: CLI parsing

### eBPF
- `aya-ebpf`: eBPF programming framework
- `network-types`: Network protocol types
- `aya-log-ebpf`: Logging from eBPF

## Future Enhancements

Potential improvements:

1. **Path MTU Discovery**: Automatic MTU adjustment
2. **IPsec Integration**: Built-in encryption support
3. **Statistics**: Packet counters and metrics
4. **Dynamic Routing**: Support for route changes
5. **Multi-tunnel**: Multiple tunnels per instance
6. **Monitoring**: Prometheus metrics export
7. **QoS**: Traffic shaping and prioritization
