fn main() {
    let p = vec![0u8; 16];
    drop(p);
    drop(p);
}
