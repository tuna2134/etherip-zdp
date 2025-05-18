#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    helpers::gen::bpf_xdp_adjust_head,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv6Hdr,
};

#[map]
static MACADDRESS: HashMap<u32, [u8; 6]> = HashMap::<u32, [u8; 6]>::with_max_entries(4, 0);

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
    match try_encap(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_encap(ctx: XdpContext) -> Result<u32, ()> {
    unsafe {
        let x = bpf_xdp_adjust_head(
            ctx.ctx,
            -((EthHdr::LEN + Ipv6Hdr::LEN + EtherIPHdr::LEN) as i32),
        );
        info!(&ctx, "adjust_head: {}", x);
        if x != 0 {
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
    }
    Ok(xdp_action::XDP_PASS)
}

#[repr(C)]
struct EtherIPHdr {
    version: u8,
    reserved: u8,
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
