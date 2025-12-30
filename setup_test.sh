#!/bin/bash
# Example setup and test script for etherip-zdp
# This demonstrates how to use the EtherIP tunnel with both IPv4 and IPv6

set -e

echo "=== EtherIP-ZDP Test Setup ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (or use sudo)"
    exit 1
fi

echo "Cleaning up any existing test interfaces..."
ip netns del host1 2>/dev/null || true
ip link del test1-veth0 2>/dev/null || true
ip link del tap0 2>/dev/null || true
ip link del br0 2>/dev/null || true

echo "Creating network namespace and veth pair..."
ip netns add host1
ip link add test1-veth0 type veth peer name test2-veth0
ip link set test2-veth0 netns host1

echo
echo "=== IPv6 Setup Example ==="
echo "Configuring IPv6 addresses..."
ip a add fd20::1/64 dev test1-veth0
ip netns exec host1 ip a add fd20::2/64 dev test2-veth0
ip link set up dev test1-veth0
ip netns exec host1 ip link set up dev test2-veth0

echo "Creating tap and bridge..."
ip tuntap add mode tap dev tap0
ip link set up dev tap0
ip link add name br0 type bridge
ip link set dev tap0 master br0
ip link set up dev br0

echo
echo "=== Alternative IPv4 Setup ==="
echo "For IPv4 tunnel, you would configure:"
echo "  ip a add 192.168.1.1/24 dev test1-veth0"
echo "  ip netns exec host1 ip a add 192.168.1.2/24 dev test2-veth0"
echo

echo "=== Running EtherIP Tunnel ==="
echo
echo "To start the IPv6 tunnel, run:"
echo "  RUST_LOG=info cargo run -r --config 'target.\"cfg(all())\".runner=\"sudo -E\"' -- \\"
echo "    --src-addr=fd20::1 --dst-addr=fd20::2 --device=tap0"
echo
echo "To start the IPv4 tunnel, run:"
echo "  RUST_LOG=info cargo run -r --config 'target.\"cfg(all())\".runner=\"sudo -E\"' -- \\"
echo "    --src-addr=192.168.1.1 --dst-addr=192.168.1.2 --device=tap0"
echo

echo "=== Packet Capture ==="
echo "To capture and verify EtherIP packets:"
echo "  tcpdump -i test1-veth0 -v -X 'ip proto 97' or 'ip6 proto 97'"
echo

echo "Setup complete! The interfaces are ready for testing."
echo "Remember to clean up when done:"
echo "  sudo ip netns del host1"
echo "  sudo ip link del test1-veth0"
echo "  sudo ip link del tap0"
echo "  sudo ip link del br0"
