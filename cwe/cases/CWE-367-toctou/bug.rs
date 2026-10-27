fn main() {
    if std::path::Path::new("/tmp").exists() {
        // window: the path can be swapped here
        let _ = std::fs::File::open("/tmp");
    }
}
