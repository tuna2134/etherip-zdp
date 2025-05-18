use anyhow::{anyhow, Context as _};
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use futures::TryStreamExt;
use mac::get_mac;
use rtnetlink::packet_route::link::LinkAttribute;
use tokio::signal;
mod mac;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    src_addr: String,
    #[clap(short, long)]
    dst_addr: String,
    #[clap(short, long)]
    device: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let Opt {
        src_addr,
        dst_addr,
        device,
    } = opt;
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    let mut addresses = handle
        .address()
        .get()
        .set_address_filter(src_addr.parse()?)
        .execute();
    let a_msg = loop {
        if let Some(msg) = addresses.try_next().await? {
            break msg;
        }
    };
    let mut links = handle
        .link()
        .get()
        .match_index(a_msg.header.index)
        .execute();
    let ifname = loop {
        match links.try_next().await? {
            Some(msg) => {
                if let Some(name) = msg.attributes.into_iter().find_map(|attr| match attr {
                    LinkAttribute::IfName(name) => Some(name),
                    _ => None,
                }) {
                    break Some(name);
                }
            }
            None => break None,
        }
    };
    let ifname = ifname.map_or_else(|| Err(anyhow!("Not found")), |x| Ok(x))?;

    let (src_macaddress, dst_macaddress) = get_mac(&ifname, dst_addr.parse()?).unwrap();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/etherip-zdp"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut Xdp = ebpf.program_mut("encap").unwrap().try_into()?;
    program.load()?;
    program.attach(&device, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut macaddress: HashMap<_, u32, [u8; 6]> =
        HashMap::try_from(ebpf.map_mut("MACADDRESS").unwrap())?;
    macaddress.insert(0, src_macaddress.octets(), 0)?;
    macaddress.insert(1, dst_macaddress.octets(), 0)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
