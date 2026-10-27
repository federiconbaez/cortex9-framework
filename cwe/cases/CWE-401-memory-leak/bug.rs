fn main() {
    let p: &'static mut [u8; 4096] = Box::leak(Box::new([0u8; 4096]));
    p[0] = 1;
}
