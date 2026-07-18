#![no_main]

use libfuzzer_sys::fuzz_target;
use runtrue_wasm_runtime::Runtime as WasmRuntime;
use std::sync::OnceLock;
use tokio::runtime::{Builder, Runtime as TokioRuntime};

const MAX_COMPONENT_BYTES: usize = 128 * 1024;

struct Harness {
    executor: TokioRuntime,
    runtime: WasmRuntime,
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| Harness {
        executor: Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("Tokio fuzz executor"),
        runtime: WasmRuntime::with_defaults().expect("runtime fuzz harness"),
    })
}

fuzz_target!(|bytes: &[u8]| {
    let harness = harness();
    let bytes = &bytes[..bytes.len().min(MAX_COMPONENT_BYTES)];
    if let Ok(program) = harness.runtime.load_bytes(bytes.to_vec()) {
        // Preparation is the admission boundary: arbitrary bytes must be
        // rejected as an ordinary error, never panic or cross into execution.
        let _ = harness.executor.block_on(program.prepare());
    }
});
