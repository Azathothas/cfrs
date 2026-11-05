//! `podssh-todo`: check the work record, or move a status and derive the
//! counts. See `TODO/RULES.md`.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = podssh_todo::run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
