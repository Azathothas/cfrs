//! Write the seeds of each target to fuzz/corpus/<target>/.
//!
//!   cargo +nightly run --manifest-path fuzz/Cargo.toml --bin seed [DIR]

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "fuzz/corpus".into());
    for (name, _) in cfrs::fuzzing::TARGETS {
        let at = std::path::Path::new(&dir).join(name);
        std::fs::create_dir_all(&at).expect("making the corpus directory");
        for (i, seed) in cfrs::fuzzing::seeds(name).iter().enumerate() {
            std::fs::write(at.join(format!("seed-{i}")), seed).expect("writing a seed");
        }
    }
}
