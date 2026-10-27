fn main() {
    let mut counter = 0i64;
    std::thread::scope(|s| {
        s.spawn(|| for _ in 0..100000 { counter += 1 });
        s.spawn(|| for _ in 0..100000 { counter += 1 });
    });
    println!("{counter}");
}
