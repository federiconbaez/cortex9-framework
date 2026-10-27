fn main() {
    let x: i32;
    if std::env::args().count() > 5 {
        x = 1;
    }
    std::process::exit(x);
}
