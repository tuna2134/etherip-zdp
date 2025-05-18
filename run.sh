sudo ip netns add host1
sudo ip link add test1-veth0 type veth peer name test2-veth0
sudo ip link set test2-veth0 netns host1
sudo ip a add fd20::1/64 dev test1-veth0
sudo ip netns exec host1 ip a add fd20::2/64 dev test2-veth0
sudo ip link set up dev test1-veth0
sudo ip netns exec host1 ip link set up dev test2-veth0
sudo ip tuntap add mode tap dev tap0
sudo ip link set up dev tap0
sudo ip a add 192.168.1.1/24 dev tap0
RUST_LOG=info cargo run -r --config 'target."cfg(all())".runner="sudo -E"' -- --src-addr=fd20::1 --dst-addr=fd20::2 --device=tap0