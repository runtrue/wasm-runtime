//! End-to-end qualification of WASIX explicit snapshot and resume semantics.

#![cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]

use std::{io::Read, sync::Arc};

use wasmer::{Engine, Module};
use wasmer_wasix::{
    Pipe, PluggableRuntime, Runtime, UnsupportedVirtualNetworking, WasiEnvBuilder,
    bin_factory::spawn_exec_module,
    journal::{JournalEntry, LogFileJournal, ReadableJournal, SnapshotTrigger},
    runtime::{
        resolver::MultiSource,
        task_manager::{VirtualTaskManagerExt, tokio::TokioTaskManager},
    },
};

const FIXTURE: &[u8] = include_bytes!("fixtures/wasix-checkpoint-number.wasm");
const VALUE: &str = "424242";

fn compiled_fixture() -> (Engine, Module) {
    let engine = Engine::default();
    let module = Module::new(&engine, FIXTURE).expect("checkpoint fixture must compile");
    (engine, module)
}

fn captured_stdout() -> (Pipe, Pipe) {
    Pipe::channel()
}

fn run_fixture(
    engine: &Engine,
    module: Module,
    arguments: &[&str],
    stdout: Pipe,
    readable_journal: Option<Arc<LogFileJournal>>,
    writable_journal: Option<Arc<LogFileJournal>>,
    stop_after_explicit_snapshot: bool,
) {
    // The checkpoint feature uses WASIX's journal-capable sys preset.
    // Neutralize its host clients, then avoid WasiRunner because it registers
    // each journal twice and loses the valid rewind state on the EOF replay.
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("WASIX task runtime must initialize");
    let runtime_handle = tokio_runtime.handle().clone();
    let _runtime_guard = runtime_handle.enter();
    let task_manager = Arc::new(TokioTaskManager::new(runtime_handle));
    let mut concrete_runtime = PluggableRuntime::new(task_manager);
    concrete_runtime.set_engine(engine.clone());
    concrete_runtime.set_networking_implementation(UnsupportedVirtualNetworking::default());
    concrete_runtime.http_client = None;
    concrete_runtime.set_source(MultiSource::default());
    assert!(concrete_runtime.http_client().is_none());
    if let Some(journal) = readable_journal {
        concrete_runtime.add_read_only_journal(journal);
    }
    if let Some(journal) = writable_journal {
        concrete_runtime.add_writable_journal(journal);
    }
    let runtime: Arc<dyn Runtime + Send + Sync> = Arc::new(concrete_runtime);

    let module_hash = module
        .info()
        .hash()
        .expect("compiled fixture must retain its content hash");
    let mut builder = WasiEnvBuilder::new("wasix-checkpoint-number");
    let (stderr, _stderr_output) = Pipe::channel();
    builder.set_runtime(runtime.clone());
    builder.set_module_hash(module_hash);
    builder.add_args(arguments.iter().copied());
    builder.set_stdout(Box::new(stdout));
    builder.set_stderr(Box::new(stderr));
    builder.with_skip_stdio_during_bootstrap(true);
    if stop_after_explicit_snapshot {
        builder.add_snapshot_trigger(SnapshotTrigger::Explicit);
        builder.with_stop_running_after_snapshot(true);
    }

    let environment = builder.build().expect("WASIX environment must build");
    let mut task =
        spawn_exec_module(module, environment, &runtime).expect("WASIX fixture task must spawn");
    let exit_code = runtime
        .task_manager()
        .spawn_and_block_on(async move { task.wait_finished().await })
        .expect("WASIX fixture task must be joinable")
        .expect("WASIX fixture task must finish without a runtime error");
    assert!(
        exit_code.is_success(),
        "WASIX fixture exited with {exit_code}"
    );
}

#[test]
fn fixture_has_the_imports_and_exports_required_for_safe_rewind() {
    let (_, module) = compiled_fixture();
    let imports = module
        .imports()
        .map(|import| (import.module().to_owned(), import.name().to_owned()))
        .collect::<Vec<_>>();
    assert!(
        imports.contains(&("wasix_32v1".to_owned(), "proc_snapshot".to_owned())),
        "fixture must explicitly request a WASIX snapshot"
    );

    let exports = module
        .exports()
        .map(|export| export.name().to_owned())
        .collect::<Vec<_>>();
    for required in [
        "asyncify_start_unwind",
        "asyncify_stop_unwind",
        "asyncify_start_rewind",
        "asyncify_stop_rewind",
        "asyncify_get_state",
        "__stack_pointer",
        "__data_end",
    ] {
        assert!(
            exports.iter().any(|export| export == required),
            "fixture is missing required export {required}"
        );
    }
}

#[test]
fn explicit_snapshot_restores_the_source_value_and_prints_once() {
    let temporary = tempfile::tempdir().expect("temporary directory must be available");
    let journal_path = temporary.path().join("checkpoint.journal");
    let (engine, module) = compiled_fixture();
    let module_hash = module
        .info()
        .hash()
        .expect("compiled fixture must retain its content hash");

    let (source_stdout, mut source_output) = captured_stdout();
    run_fixture(
        &engine,
        module.clone(),
        &[VALUE],
        source_stdout,
        None,
        Some(Arc::new(
            LogFileJournal::new(&journal_path).expect("source journal must open"),
        )),
        true,
    );

    let mut source_bytes = Vec::new();
    source_output
        .read_to_end(&mut source_bytes)
        .expect("source stdout must remain readable");
    assert_eq!(source_bytes, b"", "source must not run past the checkpoint");
    assert!(
        std::fs::metadata(&journal_path)
            .expect("journal must exist")
            .len()
            > 8,
        "checkpoint journal must contain records"
    );

    let inspection = LogFileJournal::new_readonly(&journal_path)
        .expect("completed source journal must be readable");
    let mut set_thread_records = 0;
    let mut explicit_snapshots = 0;
    let mut matching_module_records = 0;
    let mut checkpoint_end = None;
    while let Some(record) = inspection
        .read()
        .expect("self-produced journal must decode")
    {
        match &record.record {
            JournalEntry::InitModuleV1 { wasm_hash } => {
                assert_eq!(wasm_hash.as_ref(), module_hash.as_bytes());
                matching_module_records += 1;
            }
            JournalEntry::SetThreadV1 { .. } => set_thread_records += 1,
            JournalEntry::SnapshotV1 {
                trigger: SnapshotTrigger::Explicit,
                ..
            } => {
                explicit_snapshots += 1;
                checkpoint_end = Some(record.record_end);
            }
            _ => {}
        }
    }
    assert_eq!(
        matching_module_records, 1,
        "journal must bind the module hash"
    );
    assert!(set_thread_records > 0, "journal must contain thread state");
    assert_eq!(
        explicit_snapshots, 1,
        "journal must close one explicit snapshot"
    );

    // A migratable checkpoint is the durable prefix ending at SnapshotV1;
    // later worker teardown must never become part of the artifact.
    let checkpoint_path = temporary.path().join("checkpoint-prefix.journal");
    let source_journal = std::fs::read(&journal_path).expect("source journal must be readable");
    let checkpoint_end = usize::try_from(checkpoint_end.expect("snapshot boundary must exist"))
        .expect("snapshot boundary must fit in memory");
    std::fs::write(&checkpoint_path, &source_journal[..checkpoint_end])
        .expect("checkpoint prefix must be sealable");

    let (destination_stdout, mut destination_output) = captured_stdout();
    let (destination_engine, destination_module) = compiled_fixture();
    run_fixture(
        &destination_engine,
        destination_module,
        &[],
        destination_stdout,
        Some(Arc::new(
            LogFileJournal::new_readonly(&checkpoint_path).expect("destination journal must open"),
        )),
        None,
        false,
    );

    let mut destination_bytes = Vec::new();
    destination_output
        .read_to_end(&mut destination_bytes)
        .expect("destination stdout must remain readable");
    assert_eq!(destination_bytes, format!("{VALUE}\n").as_bytes());
}
