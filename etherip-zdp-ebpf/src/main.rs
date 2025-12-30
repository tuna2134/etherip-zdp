#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_DROP, XDP_PASS},
    helpers::gen::bpf_xdp_adjust_head,
    macros::{map, xdp},
    maps::{DevMap, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
};

#[map]
static MACADDRESS: HashMap<u32, [u8; 6]> = HashMap::<u32, [u8; 6]>::with_max_entries(4, 0);

#[map]
static IPADDRESS: HashMap<u32, [u8; 16]> = HashMap::<u32, [u8; 16]>::with_max_entries(4, 0);

#[map]
static DEV_MAP: DevMap = DevMap::with_max_entries(4, 0);

// IP version flag: 0 = IPv4, 1 = IPv6
#[map]
static IP_VERSION: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *mut T;
    Ok(ptr)
}

#[xdp]
pub fn encap(ctx: XdpContext) -> u32 {
    info!(&ctx, "encap");
    match try_encap(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_encap(ctx: XdpContext) -> Result<u32, ()> {
    // Get IP version (0 = IPv4, 1 = IPv6)
    let ip_version = unsafe { IP_VERSION.get(&0).copied().unwrap_or(1) };
    
    if ip_version == 0 {
        try_encap_ipv4(ctx)
    } else {
        try_encap_ipv6(ctx)
    }
}

fn try_encap_ipv4(ctx: XdpContext) -> Result<u32, ()> {
    // RFC 3378: Add EtherIP header (2 bytes) + IPv4 header (20 bytes) + Ethernet header (14 bytes)
    // Total overhead: 36 bytes
    // Note: Large packets may be fragmented by the IP layer if they exceed MTU
    unsafe {
        let x = bpf_xdp_adjust_head(
            ctx.ctx,
            -((EthHdr::LEN + Ipv4Hdr::LEN + EtherIPHdr::LEN) as i32),
        );
        info!(&ctx, "adjust_head IPv4: {}", x);
        if x < 0 {
            return Ok(XDP_PASS);
        }
    }
    let src_macaddr = if let Some(src_macaddr) = unsafe { MACADDRESS.get(&0) } {
        src_macaddr
    } else {
        return Ok(XDP_PASS);
    };
    let dst_macaddr = if let Some(dst_macaddr) = unsafe { MACADDRESS.get(&1) } {
        dst_macaddr
    } else {
        return Ok(XDP_PASS);
    };
    unsafe {
        let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;
        (*eth_hdr).ether_type = EtherType::Ipv4;
        (*eth_hdr).src_addr = *src_macaddr;
        (*eth_hdr).dst_addr = *dst_macaddr;

        let ip_hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
        (*ip_hdr).version = 4;
        (*ip_hdr).ihl = 5; // 20 bytes header (no options)
        (*ip_hdr).tos = 0;
        (*ip_hdr).protocol = IpProto::Etherip;
        (*ip_hdr).ttl = 255;
        (*ip_hdr).total_len = ((ctx.data_end() - ctx.data() - EthHdr::LEN) as u16).to_be();
        
        // Get IPv4 addresses from first 4 bytes of stored addresses
        let src_ipaddr = if let Some(addr) = IPADDRESS.get(&0) {
            u32::from_ne_bytes([addr[0], addr[1], addr[2], addr[3]]).to_be()
        } else {
            return Ok(XDP_PASS);
        };
        let dst_ipaddr = if let Some(addr) = IPADDRESS.get(&1) {
            u32::from_ne_bytes([addr[0], addr[1], addr[2], addr[3]]).to_be()
        } else {
            return Ok(XDP_PASS);
        };
        
        (*ip_hdr).src_addr = src_ipaddr;
        (*ip_hdr).dst_addr = dst_ipaddr;
        (*ip_hdr).check = 0;
        
        // Calculate IPv4 checksum
        let checksum = ipv4_checksum(ip_hdr)?;
        (*ip_hdr).check = checksum;

        let etherip_hdr = ptr_at::<EtherIPHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
        (*etherip_hdr).version = 3 << 4;
        (*etherip_hdr).reserved = 0x00;

        info!(&ctx, "IPv4 encap ok");
        return Ok(DEV_MAP.redirect(0, 0).unwrap_or(XDP_DROP));
    }
}

fn try_encap_ipv6(ctx: XdpContext) -> Result<u32, ()> {
    // RFC 3378: Add EtherIP header (2 bytes) + IPv6 header (40 bytes) + Ethernet header (14 bytes)
    // Total overhead: 56 bytes
    // Note: Large packets may be fragmented by the IP layer if they exceed MTU
    unsafe {
        let x = bpf_xdp_adjust_head(
            ctx.ctx,
            -((EthHdr::LEN + Ipv6Hdr::LEN + EtherIPHdr::LEN) as i32),
        );
        info!(&ctx, "adjust_head IPv6: {}", x);
        if x < 0 {
            return Ok(XDP_PASS);
        }
    }
    let src_macaddr = if let Some(src_macaddr) = unsafe { MACADDRESS.get(&0) } {
        src_macaddr
    } else {
        return Ok(XDP_PASS);
    };
    let dst_macaddr = if let Some(dst_macaddr) = unsafe { MACADDRESS.get(&1) } {
        dst_macaddr
    } else {
        return Ok(XDP_PASS);
    };
    unsafe {
        let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;
        (*eth_hdr).ether_type = EtherType::Ipv6;
        (*eth_hdr).src_addr = *src_macaddr;
        (*eth_hdr).dst_addr = *dst_macaddr;

        let ip_hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
        (*ip_hdr).set_version(6);
        (*ip_hdr).next_hdr = IpProto::Etherip;
        (*ip_hdr).hop_limit = 255;
        (*ip_hdr).src_addr = *if let Some(src_ipaddr) = IPADDRESS.get(&0) {
            src_ipaddr
        } else {
            return Ok(XDP_PASS);
        };
        (*ip_hdr).dst_addr = *if let Some(dst_ipaddr) = IPADDRESS.get(&1) {
            dst_ipaddr
        } else {
            return Ok(XDP_PASS);
        };
        (*ip_hdr)
            .set_payload_len((ctx.data_end() - ctx.data() - EthHdr::LEN - Ipv6Hdr::LEN) as u16);

        let etherip_hdr = ptr_at::<EtherIPHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
        (*etherip_hdr).version = 3 << 4;
        (*etherip_hdr).reserved = 0x00;

        info!(&ctx, "IPv6 encap ok");
        return Ok(DEV_MAP.redirect(0, 0).unwrap_or(XDP_DROP));
    }
    Ok(xdp_action::XDP_PASS)
}

#[xdp]
pub fn decap(ctx: XdpContext) -> u32 {
    info!(&ctx, "decap");
    match try_decap(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_decap(ctx: XdpContext) -> Result<u32, ()> {
    // Check if it's an IPv4 or IPv6 packet
    unsafe {
        let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;
        
        match (*eth_hdr).ether_type {
            EtherType::Ipv4 => try_decap_ipv4(ctx),
            EtherType::Ipv6 => try_decap_ipv6(ctx),
            _ => Ok(XDP_PASS),
        }
    }
}

fn try_decap_ipv4(ctx: XdpContext) -> Result<u32, ()> {
    // RFC 3378: Validate and remove EtherIP encapsulation for IPv4
    unsafe {
        let ip_hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
        // Check if it's EtherIP protocol (97)
        if (*ip_hdr).protocol != IpProto::Etherip {
            return Ok(XDP_PASS);
        }
        
        let etherip_hdr = ptr_at::<EtherIPHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
        // Verify EtherIP version is 3
        if (*etherip_hdr).version != 0x30 {
            return Ok(XDP_PASS);
        }
        // Remove outer headers: Ethernet (14) + IPv4 (20) + EtherIP (2) = 36 bytes
        let x = bpf_xdp_adjust_head(
            ctx.ctx,
            (EthHdr::LEN + Ipv4Hdr::LEN + EtherIPHdr::LEN) as i32,
        );
        if x < 0 {
            return Ok(XDP_PASS);
        }
        info!(&ctx, "IPv4 decap ok");
        return Ok(DEV_MAP.redirect(1, 0).unwrap_or(XDP_DROP));
    }
}

fn try_decap_ipv6(ctx: XdpContext) -> Result<u32, ()> {
    // RFC 3378: Validate and remove EtherIP encapsulation for IPv6
    unsafe {
        let ip_hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
        // Check if it's EtherIP protocol (97)
        if (*ip_hdr).next_hdr != IpProto::Etherip {
            return Ok(XDP_PASS);
        }
        
        let etherip_hdr = ptr_at::<EtherIPHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
        // Verify EtherIP version is 3
        if (*etherip_hdr).version != 0x30 {
            return Ok(XDP_PASS);
        }
        // Remove outer headers: Ethernet (14) + IPv6 (40) + EtherIP (2) = 56 bytes
        let x = bpf_xdp_adjust_head(
            ctx.ctx,
            (EthHdr::LEN + Ipv6Hdr::LEN + EtherIPHdr::LEN) as i32,
        );
        if x < 0 {
            return Ok(XDP_PASS);
        }
        info!(&ctx, "IPv6 decap ok");
        return Ok(DEV_MAP.redirect(1, 0).unwrap_or(XDP_DROP));
    }
}

// Calculate IPv4 header checksum
#[inline(always)]
unsafe fn ipv4_checksum(ip_hdr: *const Ipv4Hdr) -> Result<u16, ()> {
    let mut sum: u32 = 0;
    let hdr_ptr = ip_hdr as *const u16;
    
    // Sum all 16-bit words in the header (10 words for 20-byte header)
    for i in 0..10 {
        sum += u16::from_be(core::ptr::read_unaligned(hdr_ptr.add(i))) as u32;
    }
    
    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    Ok(!sum as u16)
}

// RFC 3378 EtherIP Header
// 
//  0                   1
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Version  |      Reserved     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Version: 4 bits, must be 3 (0x3)
// Reserved: 12 bits, must be 0
#[repr(C)]
struct EtherIPHdr {
    version: u8,   // Version (4 bits) + first 4 bits of reserved
    reserved: u8,  // Last 8 bits of reserved
}

impl EtherIPHdr {
    const LEN: usize = mem::size_of::<Self>();
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
