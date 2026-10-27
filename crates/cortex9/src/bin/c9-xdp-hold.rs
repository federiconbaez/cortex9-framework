// SPDX-License-Identifier: Apache-2.0
//! Keep an XDP program attached for the duration of stdin.
fn main() {
    let mut a = std::env::args().skip(1);
    let policy = a.next().expect("policy");
    let pin = a.next().expect("pin-dir");
    let iface = a.next().expect("iface");
    let src = std::fs::read_to_string(&policy).expect("read policy");
    let plan = c9_policy::compile(&src).expect("compile").plan;
    let mut fw = c9_xdp::Firewall::load(Some(std::path::Path::new(&pin))).expect("load");
    let r = fw.maps.apply(&plan).expect("apply");
    fw.attach(&iface, true).expect("attach");
    eprintln!(
        "READY program_id={} epoch={}",
        fw.program_id().unwrap(),
        r.epoch
    );
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}
