fn main() {
    let argc = std::env::args().count();
    let pkt: Vec<u8> = (0..8).map(|i| (i + argc + 30) as u8).collect();
    let len = pkt[0] as usize;
    println!("{}", pkt[len]);
}
