//! End-to-end checkpoint migration between isolated WASIX worker processes.

#![cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]

use std::time::Duration;

use runtrue_wasm_runtime::{
    CheckpointAuthenticationKey, CommandInput, WASIX_WORKER_PROTOCOL_VERSION,
    WasixCheckpointBinding, WasixCheckpointCodec, WasixWorkerConfig, capture_wasix_checkpoint,
    restore_wasix_checkpoint,
};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/wasix-checkpoint-number.wasm");
const VALUE: &str = "424242";
const WORKER: &str = env!("CARGO_BIN_EXE_runtrue-wasix-worker");

#[tokio::test]
async fn moves_a_checkpoint_from_one_worker_to_another() {
    let module_sha256 = hex::encode(Sha256::digest(FIXTURE));
    let binding = WasixCheckpointBinding::new(
        format!("sha256:{}", "1".repeat(64)),
        module_sha256.clone(),
        "_start",
        "worker-migration-test",
        1,
    )
    .expect("fixture binding must be valid");

    let source = capture_wasix_checkpoint(
        &worker_config(),
        binding.clone(),
        FIXTURE.to_vec(),
        CommandInput::default().with_args([VALUE]),
    )
    .await
    .expect("source worker must capture the explicit checkpoint");
    assert!(source.stdout.is_empty(), "source must stop before stdout");
    assert!(source.stderr.is_empty(), "source must not emit stderr");

    let source_process_id = source.worker.process_id;
    let journal_sha256 = source.journal_sha256.clone();
    let codec = WasixCheckpointCodec::new(CheckpointAuthenticationKey::new([7; 32]));
    let artifact = codec
        .seal_capture(source.journal())
        .expect("source checkpoint must seal for transport");
    let checkpoint = codec
        .open(&binding, &artifact)
        .expect("transported checkpoint must authenticate");
    assert_eq!(
        checkpoint.artifact_sha256(),
        hex::encode(Sha256::digest(&artifact))
    );

    // The destination receives no arguments. Its restored state is the only
    // source of the value printed after the checkpoint resumes.
    let destination = restore_wasix_checkpoint(&worker_config(), checkpoint, FIXTURE.to_vec())
        .await
        .expect("destination worker must restore the checkpoint");

    assert_ne!(source_process_id, destination.worker.process_id);
    assert_ne!(source_process_id, std::process::id());
    assert_ne!(destination.worker.process_id, std::process::id());
    assert_eq!(destination.stdout, b"424242\n");
    assert_eq!(destination.binding, binding);
    assert_eq!(destination.module_sha256, module_sha256);
    assert_eq!(destination.journal_sha256, journal_sha256);
    assert_eq!(
        destination.worker.protocol_version,
        WASIX_WORKER_PROTOCOL_VERSION
    );
    assert!(source.worker.isolation.no_new_privileges);
    assert!(destination.worker.isolation.no_new_privileges);
    assert_eq!(source.worker.isolation.capability_masks, [0; 4]);
    assert_eq!(destination.worker.isolation.capability_masks, [0; 4]);
    println!("RUNTRUE_WASIX_CHECKPOINT_MIGRATION_OK value=424242 workers=distinct");
}

fn worker_config() -> WasixWorkerConfig {
    WasixWorkerConfig::new(WORKER)
        .with_handshake_timeout(Duration::from_secs(30))
        .with_allowed_supplementary_groups(expected_worker_groups())
}

fn expected_worker_groups() -> Vec<u32> {
    if rustix::process::geteuid().is_root() {
        return Vec::new();
    }
    let mut groups: Vec<_> = rustix::process::getgroups()
        .expect("supplementary groups must be readable")
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .collect();
    groups.sort_unstable();
    groups.dedup();
    groups
}
