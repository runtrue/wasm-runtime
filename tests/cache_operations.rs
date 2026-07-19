//! Operational coverage for the authenticated disk AOT cache.

use runtrue_wasm_runtime::{
    AotAuthenticationKey, DiskCacheConfig, Error, PackageTier, Runtime, RuntimeConfig,
};
use serde_json::Value;
use std::{fs, path::Path, time::Duration};
use tempfile::TempDir;

const COMPONENT: &[u8] = include_bytes!("fixtures/p2-http-hello.component.wasm");

#[test]
fn authentication_key_rotation_fails_closed_until_the_cache_is_cleared() {
    let directory = TempDir::new().expect("cache directory");
    prepare_once(directory.path(), [1; 32]);

    let runtime = build_runtime(directory.path(), [2; 32], usize::MAX);
    let program = runtime.load_bytes(COMPONENT).expect("program");
    assert_eq!(program.tier(), PackageTier::DiskAot);
    let error = tokio()
        .block_on(program.prepare())
        .expect_err("old key must fail");
    assert!(matches!(error, Error::Cache(message) if message == "artifact authentication failed"));

    clear_cache_files(directory.path());
    let runtime = build_runtime(directory.path(), [2; 32], usize::MAX);
    let program = runtime.load_bytes(COMPONENT).expect("program");
    tokio()
        .block_on(program.prepare())
        .expect("recompile after clear");
    assert_eq!(program.tier(), PackageTier::Warm);
}

#[test]
fn incompatible_wasmtime_identity_fails_closed_until_the_cache_is_cleared() {
    let directory = TempDir::new().expect("cache directory");
    prepare_once(directory.path(), [3; 32]);
    let metadata = only_file_with_suffix(directory.path(), ".aot.json");
    let mut value: Value =
        serde_json::from_slice(&fs::read(&metadata).expect("metadata")).expect("valid metadata");
    value["identity"]["wasmtime_version"] = Value::String("0.0.0-incompatible".to_owned());
    fs::write(&metadata, serde_json::to_vec(&value).expect("encode")).expect("tamper identity");

    let runtime = build_runtime(directory.path(), [3; 32], usize::MAX);
    let program = runtime.load_bytes(COMPONENT).expect("program");
    let error = tokio()
        .block_on(program.prepare())
        .expect_err("identity must fail");
    assert!(
        matches!(error, Error::Cache(message) if message == "artifact identity is incompatible")
    );

    clear_cache_files(directory.path());
    let runtime = build_runtime(directory.path(), [3; 32], usize::MAX);
    tokio()
        .block_on(runtime.load_bytes(COMPONENT).expect("program").prepare())
        .expect("recompile after clear");
}

#[test]
fn cache_quota_failure_retains_the_compiled_component_without_a_partial_entry() {
    let directory = TempDir::new().expect("cache directory");
    let runtime = build_runtime(directory.path(), [4; 32], 1);
    let program = runtime.load_bytes(COMPONENT).expect("program");
    tokio()
        .block_on(program.prepare())
        .expect("disk quota is only a cache miss");
    assert_eq!(program.tier(), PackageTier::Warm);
    assert_eq!(runtime.metrics().disk_publish_failures, 1);
    assert!(cache_files(directory.path()).is_empty());
}

#[test]
fn interrupted_and_malformed_entries_fail_closed_and_can_be_recovered() {
    let directory = TempDir::new().expect("cache directory");
    prepare_once(directory.path(), [5; 32]);
    let artifact = only_file_with_suffix(directory.path(), ".aot");
    let metadata = only_file_with_suffix(directory.path(), ".aot.json");

    fs::remove_file(&metadata).expect("simulate interrupted metadata publish");
    let runtime = build_runtime(directory.path(), [5; 32], usize::MAX);
    let program = runtime.load_bytes(COMPONENT).expect("program");
    assert_eq!(program.tier(), PackageTier::Cold);
    assert!(matches!(
        tokio().block_on(program.prepare()),
        Err(Error::Cache(_))
    ));

    fs::remove_file(&artifact).expect("remove orphan");
    prepare_once(directory.path(), [5; 32]);
    let metadata = only_file_with_suffix(directory.path(), ".aot.json");
    fs::write(&metadata, b"not-json").expect("corrupt metadata");
    let runtime = build_runtime(directory.path(), [5; 32], usize::MAX);
    let program = runtime.load_bytes(COMPONENT).expect("program");
    assert!(matches!(
        tokio().block_on(program.prepare()),
        Err(Error::Cache(_))
    ));

    clear_cache_files(directory.path());
    prepare_once(directory.path(), [5; 32]);
}

#[test]
fn concurrent_publishers_leave_one_loadable_authenticated_entry() {
    let directory = TempDir::new().expect("cache directory");
    let first = build_runtime(directory.path(), [6; 32], usize::MAX)
        .load_bytes(COMPONENT)
        .expect("first program");
    let second = build_runtime(directory.path(), [6; 32], usize::MAX)
        .load_bytes(COMPONENT)
        .expect("second program");
    tokio().block_on(async {
        let (first, second) = tokio::join!(first.prepare(), second.prepare());
        first.expect("first publisher");
        second.expect("second publisher");
    });

    assert_eq!(cache_files(directory.path()).len(), 2);
    let runtime = build_runtime(directory.path(), [6; 32], usize::MAX);
    let program = runtime.load_bytes(COMPONENT).expect("program");
    assert_eq!(program.tier(), PackageTier::DiskAot);
    tokio()
        .block_on(program.prepare())
        .expect("authenticated reload");
}

#[cfg(target_os = "linux")]
#[test]
fn read_only_cache_location_is_rejected_during_runtime_construction() {
    let root = format!("/proc/runtrue-wasm-cache-test-{}", std::process::id());
    let config = RuntimeConfig {
        disk_cache: Some(DiskCacheConfig::new(
            root,
            AotAuthenticationKey::new([7; 32]),
        )),
        ..RuntimeConfig::default()
    };
    assert!(matches!(Runtime::new(config), Err(Error::Io(_))));
}

fn build_runtime(root: &Path, key: [u8; 32], max_entry_bytes: usize) -> Runtime {
    let mut disk = DiskCacheConfig::new(root, AotAuthenticationKey::new(key));
    disk.max_entry_bytes = max_entry_bytes;
    Runtime::new(RuntimeConfig {
        disk_cache: Some(disk),
        epoch_interval: Duration::from_millis(1),
        ..RuntimeConfig::default()
    })
    .expect("runtime")
}

fn prepare_once(root: &Path, key: [u8; 32]) {
    let runtime = build_runtime(root, key, usize::MAX);
    let program = runtime.load_bytes(COMPONENT).expect("program");
    tokio().block_on(program.prepare()).expect("prepare");
}

fn tokio() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("Tokio runtime")
}

fn cache_files(root: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(root)
        .expect("read cache")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.is_file())
        .collect()
}

fn only_file_with_suffix(root: &Path, suffix: &str) -> std::path::PathBuf {
    let matches = cache_files(root)
        .into_iter()
        .filter(|path| path.to_string_lossy().ends_with(suffix))
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "expected one {suffix} file");
    matches.into_iter().next().expect("one matching file")
}

fn clear_cache_files(root: &Path) {
    for path in cache_files(root) {
        fs::remove_file(path).expect("remove cache file");
    }
}
