//! Link and initialization gate for the optional WASIX dependency cohort.

#![cfg(feature = "wasix")]
#![allow(missing_docs)]

use runtrue_wasm_runtime::Runtime;
use wasmer::{Engine, Module};

#[test]
fn wasmtime_and_wasix_cohort_initialize_together() {
    let _runtime = Runtime::with_defaults().expect("initialize the Wasmtime runtime");

    let compiler = wasmer::sys::Cranelift::default();
    let native_engine = wasmer::sys::EngineBuilder::new(compiler).engine();
    let engine = Engine::from(native_engine);
    let module = Module::new(&engine, "(module (func (export \"run\")))")
        .expect("compile a minimal module with Wasmer");

    assert!(module.exports().any(|export| export.name() == "run"));
    assert!(
        wasmer_package::utils::from_bytes(Vec::new()).is_err(),
        "the pinned package parser should reject an empty artifact"
    );

    // Keeping these types in the same test binary catches incompatible cohort
    // changes even before the execution backend is introduced.
    assert!(std::any::type_name::<wasmer_wasix::PluggableRuntime>().contains("PluggableRuntime"));
    assert!(std::any::type_name::<webc::Container>().contains("Container"));
}
