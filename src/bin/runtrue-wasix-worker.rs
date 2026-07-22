//! Out-of-process worker entry point for the optional WASIX backend.

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--protocol-probe"))
        || arguments.next().is_some()
    {
        eprintln!("usage: runtrue-wasix-worker --protocol-probe");
        std::process::exit(64);
    }
    if let Err(error) = runtrue_wasm_runtime::write_wasix_worker_probe(std::io::stdout().lock()) {
        eprintln!("{error}");
        std::process::exit(70);
    }
}
