fn main() {
    let mut a = [0i32; 4];
    let i = std::env::args().count() + 3;
    a[i] = 1;
    std::process::exit(a[0]);
}
