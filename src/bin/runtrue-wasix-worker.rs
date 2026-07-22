//! Out-of-process worker entry point for the optional WASIX backend.

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let operation = arguments.next();
    if arguments.next().is_some() {
        eprintln!(
            "usage: runtrue-wasix-worker (--protocol-probe|--checkpoint-transport-probe|--checkpoint-restore|--checkpoint-capture)"
        );
        std::process::exit(64);
    }
    let result = match operation.as_deref() {
        Some(value) if value == std::ffi::OsStr::new("--protocol-probe") => {
            runtrue_wasm_runtime::write_wasix_worker_probe(std::io::stdout().lock())
        }
        Some(value) if value == std::ffi::OsStr::new("--checkpoint-transport-probe") => {
            runtrue_wasm_runtime::write_wasix_checkpoint_transport_probe(
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            )
        }
        #[cfg(feature = "wasix-checkpoint")]
        Some(value) if value == std::ffi::OsStr::new("--checkpoint-restore") => {
            runtrue_wasm_runtime::write_wasix_checkpoint_restore(
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            )
        }
        #[cfg(feature = "wasix-checkpoint")]
        Some(value) if value == std::ffi::OsStr::new("--checkpoint-capture") => {
            runtrue_wasm_runtime::write_wasix_checkpoint_capture(
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            )
        }
        _ => {
            eprintln!(
                "usage: runtrue-wasix-worker (--protocol-probe|--checkpoint-transport-probe|--checkpoint-restore|--checkpoint-capture)"
            );
            std::process::exit(64);
        }
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(70);
    }
}
