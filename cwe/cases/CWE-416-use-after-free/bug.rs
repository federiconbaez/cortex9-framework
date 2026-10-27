fn main() {
    let p = Box::new(5);
    drop(p);
    println!("{}", *p);
}
