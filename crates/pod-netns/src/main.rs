fn main() {
    // args() panics on an argument that is not UTF-8.
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    std::process::exit(pod_netns::main_with_args(&argv));
}
