//! End-to-end destination-worker restore of an authenticated WASIX checkpoint.

#![cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]

use std::{
    io::{Seek as _, SeekFrom, Write as _},
    net::Shutdown,
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use runtrue_wasm_runtime::{
    CheckpointAuthenticationKey, Error, WASIX_COHORT_ID, WASIX_WORKER_PROTOCOL_VERSION,
    WasixCheckpointBinding, WasixCheckpointCodec, WasixCheckpointRestoreFailureReason,
    WasixCheckpointRestorePhase, WasixWorkerConfig, restore_wasix_checkpoint,
};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt as _;
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
const WORKER: &str = env!("CARGO_BIN_EXE_runtrue-wasix-worker");

#[tokio::test]
async fn restores_the_source_argument_in_a_fresh_destination_worker() {
    let journal = tokio::task::spawn_blocking(capture_checkpoint_prefix)
        .await
        .expect("source checkpoint capture must be joinable");
    let module_sha256 = hex::encode(Sha256::digest(FIXTURE));
    let journal_sha256 = hex::encode(Sha256::digest(&journal));
    let binding = WasixCheckpointBinding::new(
        format!("sha256:{}", "1".repeat(64)),
        module_sha256.clone(),
        "_start",
        "destination-restore-test",
        1,
    )
    .expect("fixture binding must be valid");
    let checkpoint = authenticated_checkpoint(&binding, &journal);

    // There is deliberately no destination argument parameter: the value must
    // come exclusively from the source worker's restored checkpoint state.
    let metadata = restore_wasix_checkpoint(
        &WasixWorkerConfig::new(WORKER)
            .with_handshake_timeout(Duration::from_secs(30))
            .with_allowed_supplementary_groups(expected_worker_groups()),
        checkpoint,
        FIXTURE.to_vec(),
    )
    .await
    .expect("destination worker must restore the authenticated checkpoint");

    assert_eq!(metadata.stdout, format!("{VALUE}\n").as_bytes());
    assert_eq!(metadata.stderr, format!("{VALUE}\n").as_bytes());
    assert!(metadata.worker_diagnostics.is_empty());
    assert_eq!(metadata.binding, binding);
    assert_eq!(metadata.module_sha256, module_sha256);
    assert_eq!(metadata.journal_sha256, journal_sha256);
    assert_eq!(
        metadata.worker.protocol_version,
        WASIX_WORKER_PROTOCOL_VERSION
    );
    assert_ne!(metadata.worker.process_id, std::process::id());
    assert!(metadata.worker.isolation.no_new_privileges);
    assert_eq!(metadata.worker.isolation.capability_masks, [0; 4]);
}

#[tokio::test]
async fn rejects_a_checkpoint_from_a_different_worker_build() {
    let journal = tokio::task::spawn_blocking(capture_checkpoint_prefix)
        .await
        .expect("source checkpoint capture must be joinable");
    let binding = WasixCheckpointBinding::new(
        format!("sha256:{}", "1".repeat(64)),
        hex::encode(Sha256::digest(FIXTURE)),
        "_start",
        "different-worker-build-test",
        1,
    )
    .expect("fixture binding must be valid");
    let checkpoint = authenticated_checkpoint_for_worker(&binding, &journal, &"0".repeat(64));

    let error = restore_wasix_checkpoint(
        &WasixWorkerConfig::new(WORKER).with_allowed_supplementary_groups(expected_worker_groups()),
        checkpoint,
        FIXTURE.to_vec(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, Error::Checkpoint(message) if message.contains("worker build")),
        "{error:?}"
    );
}

#[tokio::test]
async fn restore_waits_for_execute_authorization() {
    let journal = tokio::task::spawn_blocking(capture_checkpoint_prefix)
        .await
        .expect("source checkpoint capture must be joinable");
    let mut module = sealed_restore_input("module", FIXTURE);
    module
        .seek(SeekFrom::End(0))
        .expect("module cursor must move to EOF");
    let journal_input = sealed_restore_input("journal", &journal);
    let (mut control, child_control) = restore_control_channel();
    let mut child = tokio::process::Command::new(WORKER)
        .arg("--checkpoint-restore")
        .env_clear()
        .current_dir("/")
        .stdin(child_control)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("restore worker must spawn");
    let mut stdout = child.stdout.take().expect("worker stdout must be piped");

    let ready: runtrue_wasm_runtime::WasixWorkerMetadata =
        serde_json::from_slice(&read_test_frame(&mut stdout).await)
            .expect("worker Ready frame must decode");
    assert_eq!(ready.protocol_version, WASIX_WORKER_PROTOCOL_VERSION);
    assert_ne!(ready.process_id, std::process::id());

    send_restore_descriptor(&control, &module, b'M');
    send_restore_descriptor(&control, &journal_input, b'C');
    let acknowledgement: serde_json::Value =
        serde_json::from_slice(&read_test_frame(&mut stdout).await)
            .expect("restore acknowledgement must decode");
    assert_eq!(acknowledgement["moduleBytes"], FIXTURE.len());
    assert_eq!(
        acknowledgement["moduleSha256"],
        hex::encode(Sha256::digest(FIXTURE))
    );
    assert_eq!(acknowledgement["journalBytes"], journal.len());
    assert_eq!(
        acknowledgement["journalSha256"],
        hex::encode(Sha256::digest(&journal))
    );

    match tokio::time::timeout(
        Duration::from_millis(100),
        read_test_frame_result(&mut stdout),
    )
    .await
    {
        Err(_) => {}
        Ok(Ok(frame)) => {
            panic!("restore worker emitted a completion before Execute authorization: {frame:?}")
        }
        Ok(Err(error)) => {
            panic!("restore worker exited before Execute authorization instead of waiting: {error}")
        }
    }

    control
        .write_all(b"E")
        .expect("Execute authorization must be writable");
    control
        .shutdown(Shutdown::Write)
        .expect("Execute authorization must end at EOF");
    drop(control);

    let completion: serde_json::Value = serde_json::from_slice(&read_test_frame(&mut stdout).await)
        .expect("restore completion must decode");
    let output = read_test_frame(&mut stdout).await;
    let error_output = read_test_frame(&mut stdout).await;
    assert_eq!(completion["exitCode"], 0);
    assert_eq!(completion["stdoutBytes"], output.len());
    assert_eq!(
        completion["stdoutSha256"],
        hex::encode(Sha256::digest(&output))
    );
    assert_eq!(output, format!("{VALUE}\n").as_bytes());
    assert_eq!(completion["stderrBytes"], error_output.len());
    assert_eq!(
        completion["stderrSha256"],
        hex::encode(Sha256::digest(&error_output))
    );
    assert_eq!(error_output, format!("{VALUE}\n").as_bytes());

    let mut trailing = [0_u8; 1];
    assert_eq!(
        stdout
            .read(&mut trailing)
            .await
            .expect("worker stdout EOF must be readable"),
        0
    );
    assert!(
        child
            .wait()
            .await
            .expect("restore worker must be waitable")
            .success()
    );
}

#[tokio::test]
async fn reports_bounded_redacted_worker_diagnostics_for_restore_failure() {
    let journal = tokio::task::spawn_blocking(capture_checkpoint_prefix)
        .await
        .expect("source checkpoint capture must be joinable");
    let other_module = wat::parse_str("(module (func (export \"_start\")))")
        .expect("diagnostic fixture must compile to WebAssembly");
    let binding = WasixCheckpointBinding::new(
        format!("sha256:{}", "1".repeat(64)),
        hex::encode(Sha256::digest(&other_module)),
        "_start",
        "destination-diagnostic-test",
        1,
    )
    .expect("diagnostic binding must be valid");
    let checkpoint = authenticated_checkpoint(&binding, &journal);

    let error = restore_wasix_checkpoint(
        &WasixWorkerConfig::new(WORKER)
            .with_handshake_timeout(Duration::from_secs(30))
            .with_allowed_supplementary_groups(expected_worker_groups()),
        checkpoint,
        other_module,
    )
    .await
    .expect_err("a journal captured from another module must fail in the worker");

    let display = error.to_string();
    let debug = format!("{error:?}");
    let Error::CheckpointRestore(failure) = error else {
        panic!("restore failure must retain its structured phase: {error:?}");
    };
    assert_eq!(failure.phase(), WasixCheckpointRestorePhase::Execution);
    assert_eq!(
        failure.reason(),
        WasixCheckpointRestoreFailureReason::Runtime
    );
    assert!(!failure.diagnostics().is_empty());
    assert!(!failure.diagnostics().is_truncated());
    let diagnostics = String::from_utf8_lossy(failure.diagnostics().as_bytes());
    assert!(diagnostics.contains("restore journal module hash does not match"));
    assert!(!display.contains("restore journal module hash"));
    assert!(!debug.contains("restore journal module hash"));
}

fn capture_checkpoint_prefix() -> Vec<u8> {
    let temporary = tempfile::tempdir().expect("temporary directory must be available");
    let journal_path = temporary.path().join("source.journal");
    let engine = Engine::default();
    let module = Module::new(&engine, FIXTURE).expect("checkpoint fixture must compile");
    let module_hash = module
        .info()
        .hash()
        .expect("compiled fixture must retain its content hash");
    let (source_stdout, mut source_output) = Pipe::channel();

    run_source_to_explicit_snapshot(
        &engine,
        module,
        source_stdout,
        Arc::new(LogFileJournal::new(&journal_path).expect("source journal must open")),
    );

    let mut source_bytes = Vec::new();
    std::io::Read::read_to_end(&mut source_output, &mut source_bytes)
        .expect("source stdout must remain readable");
    assert!(
        source_bytes.is_empty(),
        "source worker must not run past its checkpoint"
    );

    let inspection = LogFileJournal::new_readonly(&journal_path)
        .expect("completed source journal must be readable");
    let mut matching_module_records = 0;
    let mut set_thread_records = 0;
    let mut explicit_snapshots = 0;
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
    assert_eq!(matching_module_records, 1);
    assert!(set_thread_records > 0);
    assert_eq!(explicit_snapshots, 1);

    let journal = std::fs::read(&journal_path).expect("source journal must be readable");
    let checkpoint_end = usize::try_from(checkpoint_end.expect("snapshot boundary must exist"))
        .expect("snapshot boundary must fit in memory");
    journal[..checkpoint_end].to_vec()
}

fn run_source_to_explicit_snapshot(
    engine: &Engine,
    module: Module,
    stdout: Pipe,
    journal: Arc<LogFileJournal>,
) {
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
    concrete_runtime.add_writable_journal(journal);
    let runtime: Arc<dyn Runtime + Send + Sync> = Arc::new(concrete_runtime);

    let module_hash = module
        .info()
        .hash()
        .expect("compiled fixture must retain its content hash");
    let mut builder = WasiEnvBuilder::new("wasix-checkpoint-number");
    builder.set_runtime(runtime.clone());
    builder.set_module_hash(module_hash);
    builder.add_args([VALUE]);
    builder.set_stdout(Box::new(stdout));
    builder.with_skip_stdio_during_bootstrap(true);
    builder.add_snapshot_trigger(SnapshotTrigger::Explicit);
    builder.with_stop_running_after_snapshot(true);

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

fn authenticated_checkpoint(
    binding: &WasixCheckpointBinding,
    journal: &[u8],
) -> runtrue_wasm_runtime::VerifiedWasixCheckpoint {
    authenticated_checkpoint_for_worker(binding, journal, &worker_build_sha256())
}

fn authenticated_checkpoint_for_worker(
    binding: &WasixCheckpointBinding,
    journal: &[u8],
    worker_build_sha256: &str,
) -> runtrue_wasm_runtime::VerifiedWasixCheckpoint {
    use hmac::{Hmac, Mac as _};

    type HmacSha256 = Hmac<Sha256>;
    let metadata = serde_json::to_vec(&serde_json::json!({
        "binding": binding,
        "runtimeVersion": env!("CARGO_PKG_VERSION"),
        "workerProtocolVersion": WASIX_WORKER_PROTOCOL_VERSION,
        "cohortId": WASIX_COHORT_ID,
        "workerBuildSha256": worker_build_sha256,
        "engineProfile": "runtrue-wasix-engine-v1",
        "platform": format!(
            "{};endian={};pointer={}",
            env!("RUNTRUE_BUILD_TARGET"),
            if cfg!(target_endian = "little") { "little" } else { "big" },
            usize::BITS,
        ),
        "journalFormat": "wasmer-log-file-v1",
        "executionAbi": "wasix_32v1+asyncify",
        "isolationPolicy": "runtrue-wasix-isolation-v1",
        "snapshotTrigger": "explicit",
        "journalSha256": hex::encode(Sha256::digest(journal)),
    }))
    .expect("checkpoint metadata must encode");
    let mut artifact = Vec::new();
    artifact.extend_from_slice(b"RTWCPKT\0");
    artifact.extend_from_slice(&2_u16.to_be_bytes());
    artifact.extend_from_slice(
        &u32::try_from(metadata.len())
            .expect("metadata length must fit u32")
            .to_be_bytes(),
    );
    artifact.extend_from_slice(
        &u64::try_from(journal.len())
            .expect("journal length must fit u64")
            .to_be_bytes(),
    );
    artifact.extend_from_slice(&metadata);
    artifact.extend_from_slice(journal);
    let mut mac = HmacSha256::new_from_slice(&[7; 32]).expect("HMAC key must be valid");
    mac.update(b"runtrue-wasm-runtime.wasix-checkpoint.v2\0");
    mac.update(&artifact);
    artifact.extend_from_slice(&mac.finalize().into_bytes());

    WasixCheckpointCodec::new(CheckpointAuthenticationKey::new([7; 32]))
        .open(binding, &artifact)
        .expect("real captured checkpoint must authenticate and validate")
}

fn worker_build_sha256() -> String {
    hex::encode(Sha256::digest(
        std::fs::read(WORKER).expect("worker executable must be readable"),
    ))
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

fn sealed_restore_input(name: &str, bytes: &[u8]) -> std::fs::File {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

    let descriptor = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
        .expect("restore memfd must be creatable");
    let mut file = std::fs::File::from(descriptor);
    file.write_all(bytes)
        .expect("restore memfd must be writable before sealing");
    file.seek(SeekFrom::Start(0))
        .expect("restore memfd must rewind before sealing");
    fcntl_add_seals(
        &file,
        SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
    )
    .expect("restore memfd must accept all required seals");
    file
}

fn restore_control_channel() -> (std::os::unix::net::UnixStream, Stdio) {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    let (parent, child) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("restore control socketpair must be creatable");
    (
        std::os::unix::net::UnixStream::from(parent),
        Stdio::from(std::fs::File::from(child)),
    )
}

fn send_restore_descriptor(
    control: &std::os::unix::net::UnixStream,
    input: &std::fs::File,
    marker: u8,
) {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    use std::{io::IoSlice, mem::MaybeUninit, os::fd::AsFd as _};

    let descriptors = [input.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    assert_eq!(
        sendmsg(
            control,
            &[IoSlice::new(&[marker])],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .expect("restore descriptor must be transferable"),
        1
    );
}

async fn read_test_frame(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    read_test_frame_result(reader)
        .await
        .expect("worker frame must be readable")
}

async fn read_test_frame_result(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
) -> std::io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await?;
    let mut frame = vec![0_u8; u32::from_be_bytes(length) as usize];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}
