fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(pod_netns::main_with_args(&argv));
}
