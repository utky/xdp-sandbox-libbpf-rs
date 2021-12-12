use anyhow::{bail, Result};
use std::{thread, time};

mod bpf;
use bpf::*;

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;

    let skel_builder = UdpRedirectSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    let link = skel.progs_mut().xdp_main().attach_xdp(1)?;
    skel.links = UdpRedirectLinks {
        xdp_main: Some(link),
    };

    loop {
        thread::sleep(time::Duration::from_secs(1));
    }
}
