fn f<'a>() -> &'a i32 {
    let x = 1;
    &x
}
fn main() {
    std::process::exit(*f());
}
