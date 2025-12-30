# etherip-zdp

EtherIP (RFC 3378) implementation using Rust and eBPF/XDP with Aya-rs.

## Features

- **RFC 3378 Compliant**: Implements EtherIP protocol specification
- **Dual Stack Support**: Works with both IPv4 and IPv6 tunnel endpoints
- **High Performance**: Uses eBPF/XDP for kernel-space packet processing
- **Router Traversal**: Works across routers with standard IP routing
- **Fragmentation Support**: Handles IP fragmentation transparently
- **Zero-Copy**: Leverages XDP for efficient packet processing

For details on RFC 3378 compliance, see [RFC3378_COMPLIANCE.md](RFC3378_COMPLIANCE.md).

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

### IPv6 Example

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- \
  --src-addr=fd20::1 --dst-addr=fd20::2 --device=tap0
```

### IPv4 Example

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- \
  --src-addr=192.168.1.1 --dst-addr=192.168.1.2 --device=tap0
```

The program automatically detects whether to use IPv4 or IPv6 based on the address format.

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package etherip-zdp --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/etherip-zdp` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, etherip-zdp is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
