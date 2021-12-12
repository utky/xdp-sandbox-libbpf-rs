use anyhow::{bail, Result};
use std::{thread, time};

mod bpf;
use bpf::*;

fn main() -> Result<()> {
    let skel_builder = LocalPortLbSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    let _ = skel.progs_mut().lb_main().attach_xdp(1)?;

    loop {
        println!(".");
        thread::sleep(time::Duration::from_secs(1));
    }
}
