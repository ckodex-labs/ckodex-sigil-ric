fn main() {
    // run() renders the error itself (plain text or a JSON envelope under
    // --format json); main only maps failure to the exit code.
    if sigil_cli::run().is_err() {
        std::process::exit(1);
    }
}
