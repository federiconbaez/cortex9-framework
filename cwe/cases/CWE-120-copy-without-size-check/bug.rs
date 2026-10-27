fn main() {
    let src = [b'B'; 32];
    let mut dst = [0u8; 8];
    let n = 8 * (std::env::args().count() + 1);
    dst.copy_from_slice(&src[..n]);
    println!("{}", dst[0] as char);
}
