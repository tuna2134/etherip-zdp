# RFC 3378 Compliance

This document describes how etherip-zdp implements RFC 3378 (EtherIP).

## EtherIP Header Format

According to RFC 3378, the EtherIP header is 2 bytes:

```
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version  |      Reserved     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Version**: 4 bits, must be 3 (0x3)
- **Reserved**: 12 bits, must be 0

### Implementation

In `etherip-zdp-ebpf/src/main.rs`:
- Version field is set to `3 << 4` (0x30)
- Reserved field is set to 0x00

This matches RFC 3378 Section 3.

## IP Protocol Number

RFC 3378 specifies protocol number 97 (0x61) for EtherIP.

### Implementation

Uses `IpProto::Etherip` from the `network_types` crate, which correctly maps to protocol 97.

## IPv4 and IPv6 Support

While RFC 3378 primarily discusses IPv4, this implementation supports both:

### IPv4 Encapsulation
- Sets IPv4 header version to 4
- IHL (Internet Header Length) set to 5 (20 bytes, no options)
- Protocol field set to 97 (EtherIP)
- TTL set to 255 for maximum reach
- Calculates and sets IPv4 checksum

### IPv6 Encapsulation
- Sets IPv6 header version to 6
- Next Header field set to 97 (EtherIP)
- Hop Limit set to 255
- No checksum needed (IPv6 doesn't use header checksums)

## Fragmentation Handling

RFC 3378 Section 6 discusses fragmentation:

### Strategy
1. **IP Fragmentation**: Handled transparently by the IP layer
   - For IPv4: Standard IP fragmentation applies
   - For IPv6: Standard IPv6 fragmentation applies
   - The kernel handles reassembly before packets reach XDP

2. **MTU Considerations**:
   - EtherIP adds 2 bytes (EtherIP header)
   - IPv4 adds 20 bytes minimum
   - IPv6 adds 40 bytes
   - Total overhead: 22 bytes (IPv4) or 42 bytes (IPv6)
   - Effective MTU is reduced by this overhead

3. **Don't Fragment (DF) Flag**: 
   - Currently not explicitly set in IPv4
   - Path MTU Discovery can be added if needed

## Router Traversal

The implementation supports router traversal through:

1. **TTL/Hop Limit**: Set to 255 to allow maximum router hops
2. **Standard IP Routing**: Works with normal IP routing tables
3. **NAT Compatibility**: Since EtherIP uses standard IP headers, it can traverse NAT gateways
4. **No Special Configuration**: Routers treat these as regular IP packets

## Decapsulation

The decapsulation process:

1. Checks Ethernet type (IPv4 or IPv6)
2. Verifies IP protocol is EtherIP (97)
3. Validates EtherIP version is 3
4. Strips outer headers (Ethernet + IP + EtherIP)
5. Forwards the inner Ethernet frame

## Security Considerations

As per RFC 3378 Section 7:

- EtherIP itself provides no security
- Recommendation: Use IPsec for security
- Can be combined with VPN solutions
- Authentication and encryption should be handled at IP layer

## Differences from RFC 3378

1. **IPv6 Support**: RFC 3378 predates widespread IPv6, but this implementation supports both IPv4 and IPv6
2. **eBPF/XDP**: Uses modern eBPF/XDP for high-performance packet processing
3. **Dynamic IP Version**: Can switch between IPv4 and IPv6 based on configuration

## Testing

To verify RFC compliance:

1. Check EtherIP header format with packet capture
2. Verify protocol number is 97
3. Test fragmentation scenarios
4. Validate router traversal
5. Test with both IPv4 and IPv6
