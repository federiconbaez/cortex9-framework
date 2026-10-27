fn main() {
    let n: u16 = 65535;
    let n = n + std::env::args().count() as u16;
    let mut buf = vec![0u8; n as usize];
    buf[..64].fill(b'A');
}
