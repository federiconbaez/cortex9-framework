fn main() {
    let x = 7;
    let mut p: Option<&i32> = None;
    if std::env::args().count() > 5 {
        p = Some(&x);
    }
    std::process::exit(*p);
}
