#![no_main]

use libfuzzer_sys::fuzz_target;
use runtrue_wasm_runtime::{
    AotAuthenticationKey, DiskCacheConfig, Runtime as WasmRuntime, RuntimeConfig,
};
use std::{
    fs,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime as TokioRuntime};

const HTTP_COMPONENT: &[u8] = include_bytes!("../../tests/fixtures/p3-http-hello.component.wasm");
const MAX_METADATA_INPUT: usize = 16 * 1024;
const KEY: [u8; 32] = [0x5a; 32];

struct State {
    _directory: TempDir,
    executor: TokioRuntime,
    disk_config: DiskCacheConfig,
    artifact_path: PathBuf,
    metadata_path: PathBuf,
    artifact: Vec<u8>,
    metadata: Vec<u8>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        let directory = tempfile::tempdir().expect("temporary AOT cache");
        let disk_config = DiskCacheConfig::new(directory.path(), AotAuthenticationKey::new(KEY));
        let executor = Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("Tokio fuzz executor");
        let runtime = runtime_with_cache(disk_config.clone());
        let program = runtime
            .load_bytes(HTTP_COMPONENT)
            .expect("standard HTTP fixture");
        executor
            .block_on(program.prepare())
            .expect("publish canonical disk AOT");
        drop(program);
        drop(runtime);

        let mut entries = fs::read_dir(directory.path())
            .expect("read canonical cache")
            .map(|entry| entry.expect("cache entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        let artifact_path = entries
            .iter()
            .find(|path| path.extension().is_some_and(|extension| extension == "aot"))
            .expect("canonical AOT artifact")
            .clone();
        let metadata_path = entries
            .iter()
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .expect("canonical AOT metadata")
            .clone();
        let artifact = fs::read(&artifact_path).expect("canonical artifact bytes");
        let metadata = fs::read(&metadata_path).expect("canonical metadata bytes");

        Mutex::new(State {
            _directory: directory,
            executor,
            disk_config,
            artifact_path,
            metadata_path,
            artifact,
            metadata,
        })
    })
}

fn runtime_with_cache(disk_config: DiskCacheConfig) -> WasmRuntime {
    WasmRuntime::new(RuntimeConfig {
        disk_cache: Some(disk_config),
        ..RuntimeConfig::default()
    })
    .expect("runtime with fuzz cache")
}

fuzz_target!(|input: &[u8]| {
    let state = state().lock().expect("AOT fuzz state");
    fs::write(&state.artifact_path, &state.artifact).expect("restore artifact");
    fs::write(&state.metadata_path, &state.metadata).expect("restore metadata");

    match input.first().copied().unwrap_or_default() % 4 {
        0 => {
            let replacement = &input[1.min(input.len())..input.len().min(MAX_METADATA_INPUT)];
            fs::write(&state.metadata_path, replacement).expect("replace metadata");
        }
        1 => {
            let mut metadata = state.metadata.clone();
            for (index, byte) in input.iter().skip(1).enumerate() {
                let position = (index.wrapping_mul(257) ^ usize::from(*byte)) % metadata.len();
                metadata[position] ^= *byte | 1;
            }
            fs::write(&state.metadata_path, metadata).expect("mutate metadata");
        }
        2 => {
            let length = input
                .get(1)
                .map_or(0, |byte| usize::from(*byte) * state.artifact.len() / 255);
            fs::write(&state.artifact_path, &state.artifact[..length]).expect("truncate artifact");
        }
        _ => {
            let mut artifact = state.artifact.clone();
            for (index, byte) in input.iter().skip(1).enumerate() {
                let position = (index.wrapping_mul(65_537) ^ usize::from(*byte)) % artifact.len();
                artifact[position] ^= *byte | 1;
            }
            fs::write(&state.artifact_path, artifact).expect("mutate artifact");
        }
    }

    // A fresh runtime forces the public preparation path through disk cache
    // authentication and compatibility checks rather than an in-memory hit.
    let runtime = runtime_with_cache(state.disk_config.clone());
    let program = runtime
        .load_bytes(HTTP_COMPONENT)
        .expect("standard HTTP fixture");
    let _ = state.executor.block_on(program.prepare());
});
