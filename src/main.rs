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

    let skel_builder = LocalPortLbSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    let _ = skel.progs_mut().lb_main().attach_xdp(1)?;

    loop {
        println!(".");
        thread::sleep(time::Duration::from_secs(1));
    }
}
