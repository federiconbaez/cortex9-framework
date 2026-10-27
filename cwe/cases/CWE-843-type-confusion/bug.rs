struct A { x: i64 }
struct B { s: &'static str }
fn main() {
    let v = A { x: 0x41 };
    let p = &v as &B;
    println!("{}", p.s);
}
