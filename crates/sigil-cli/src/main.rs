fn main() {
    if let Err(err) = sigil_cli::run() {
        eprintln!("{err:?}");
        std::process::exit(1);
    }
}
