//! WASIX worker deployment protocol integration tests.

#![cfg(all(feature = "wasix", target_os = "linux"))]

use runtrue_wasm_runtime::{
    CheckpointAuthenticationKey, Error, WASIX_COHORT_ID, WASIX_WORKER_PROTOCOL_VERSION,
    WasixCheckpointBinding, WasixCheckpointCodec, WasixWorkerConfig,
    probe_wasix_checkpoint_transport, probe_wasix_worker,
};
use sha2::{Digest as _, Sha256};
use std::{io::Seek as _, process::Stdio, time::Duration};
use tokio::io::AsyncReadExt as _;

const WORKER: &str = env!("CARGO_BIN_EXE_runtrue-wasix-worker");

#[tokio::test]
async fn validates_the_explicit_worker_build_and_fresh_process() {
    let expected_groups = expected_worker_groups();
    let config = WasixWorkerConfig::new(WORKER)
        .with_allowed_supplementary_groups(expected_groups.iter().copied());
    let metadata = probe_wasix_worker(&config).await.unwrap();
    assert_eq!(metadata.protocol_version, WASIX_WORKER_PROTOCOL_VERSION);
    assert_eq!(metadata.runtime_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(metadata.cohort_id, WASIX_COHORT_ID);
    assert_ne!(metadata.process_id, std::process::id());
    let isolation = metadata.isolation;
    assert_eq!(isolation.profile_version, 2);
    assert!(!isolation.user_ids.contains(&0));
    assert!(!isolation.group_ids.contains(&0));
    assert!(!isolation.has_root_supplementary_group);
    assert!(isolation.no_new_privileges);
    assert!(!isolation.dumpable);
    assert_eq!(isolation.capability_masks, [0; 4]);
    assert_eq!(isolation.core_file_limits, [0; 2]);
    assert_eq!(isolation.file_size_limits, [512 * 1024 * 1024; 2]);
    assert_eq!(isolation.address_space_limits, [2 * 1024 * 1024 * 1024; 2]);
    assert_eq!(isolation.open_file_limits[0], isolation.open_file_limits[1]);
    assert!((1..=64).contains(&isolation.open_file_limits[0]));
    assert_eq!(isolation.supplementary_group_ids, expected_groups);

    if rustix::process::geteuid().is_root() {
        assert_eq!(isolation.user_ids, [65_534; 4]);
        assert_eq!(isolation.group_ids, [65_534; 4]);
        assert!(isolation.supplementary_group_ids.is_empty());
    }
}

#[tokio::test]
async fn transports_verified_journal_through_sealed_stdin() {
    let checkpoint = verified_transport_checkpoint();
    let expected_binding = checkpoint.binding().clone();
    let expected_bytes = u64::try_from(checkpoint.journal().len()).unwrap();
    let expected_sha256 = hex::encode(Sha256::digest(checkpoint.journal()));
    let metadata = probe_wasix_checkpoint_transport(
        &WasixWorkerConfig::new(WORKER).with_allowed_supplementary_groups(expected_worker_groups()),
        checkpoint,
    )
    .await
    .unwrap();

    assert_eq!(metadata.binding, expected_binding);
    assert_eq!(metadata.journal_bytes, expected_bytes);
    assert_eq!(metadata.journal_sha256, expected_sha256);
    assert_eq!(
        metadata.worker.protocol_version,
        WASIX_WORKER_PROTOCOL_VERSION
    );
    assert_ne!(metadata.worker.process_id, std::process::id());
    assert!(metadata.worker.isolation.no_new_privileges);
    assert_eq!(metadata.worker.isolation.capability_masks, [0; 4]);
}

#[tokio::test]
async fn checkpoint_preparation_obeys_the_complete_operation_timeout() {
    let result = probe_wasix_checkpoint_transport(
        &WasixWorkerConfig::new(WORKER)
            .with_handshake_timeout(Duration::from_nanos(1))
            .with_allowed_supplementary_groups(expected_worker_groups()),
        verified_transport_checkpoint(),
    )
    .await;

    assert!(matches!(result, Err(Error::Timeout)));
}

#[tokio::test]
async fn worker_rejects_unsealed_non_memfd_empty_and_oversized_input() {
    use rustix::fs::SealFlags;

    let required = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    for missing in [
        SealFlags::SEAL,
        SealFlags::SHRINK,
        SealFlags::GROW,
        SealFlags::WRITE,
    ] {
        let input = checkpoint_memfd(b"checkpoint", required - missing);
        assert_transport_rejected(input).await;
    }

    let empty = checkpoint_memfd(b"", required);
    assert_transport_rejected(empty).await;

    let oversized = checkpoint_memfd(b"x", SealFlags::empty());
    oversized.set_len(512 * 1024 * 1024 + 1).unwrap();
    rustix::fs::fcntl_add_seals(&oversized, required).unwrap();
    assert_transport_rejected(oversized).await;

    let ordinary = tempfile::tempfile().unwrap();
    ordinary.set_len(10).unwrap();
    assert_transport_rejected(ordinary).await;
}

#[tokio::test]
async fn sealed_input_is_immutable_and_worker_uses_positional_reads() {
    use rustix::fs::SealFlags;
    use std::io::{SeekFrom, Write as _};

    let required = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    let expected = b"cursor-independent-checkpoint";
    let mut input = checkpoint_memfd(expected, required);
    let mut retained = input.try_clone().unwrap();
    retained.seek(SeekFrom::Start(0)).unwrap();
    assert!(retained.write_all(b"mutate").is_err());
    assert!(retained.set_len(1).is_err());
    assert!(retained.set_len(1024).is_err());

    input.seek(SeekFrom::End(0)).unwrap();
    let (control, child_control) = checkpoint_control_channel();
    let mut child = tokio::process::Command::new(WORKER)
        .arg("--checkpoint-transport-probe")
        .env_clear()
        .current_dir("/")
        .stdin(child_control)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let _: serde_json::Value = serde_json::from_slice(&read_test_frame(&mut stdout).await).unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            read_test_frame_result(&mut stdout)
        )
        .await
        .is_err()
    );
    send_checkpoint_descriptor(&control, &input);
    let acknowledgement: serde_json::Value =
        serde_json::from_slice(&read_test_frame(&mut stdout).await).unwrap();
    assert_eq!(acknowledgement["journalBytes"], expected.len());
    assert_eq!(
        acknowledgement["journalSha256"],
        hex::encode(Sha256::digest(expected))
    );
    let mut trailing = [0_u8; 1];
    assert_eq!(stdout.read(&mut trailing).await.unwrap(), 0);
    assert!(child.wait().await.unwrap().success());
}

#[tokio::test]
async fn closes_inherited_host_descriptors_before_ready() {
    let sentinel = tempfile::tempfile().unwrap();
    rustix::io::fcntl_setfd(&sentinel, rustix::io::FdFlags::empty()).unwrap();
    let metadata = probe_wasix_worker(
        &WasixWorkerConfig::new(WORKER).with_allowed_supplementary_groups(expected_worker_groups()),
    )
    .await
    .unwrap();
    assert!(metadata.isolation.closed_inherited_descriptor_count >= 1);
}

#[tokio::test]
async fn rejects_implicit_and_non_worker_executables() {
    let relative = probe_wasix_worker(&WasixWorkerConfig::new("runtrue-wasix-worker"))
        .await
        .unwrap_err();
    assert!(matches!(relative, Error::Configuration(_)));

    let wrong_binary = std::env::current_exe().unwrap();
    let wrong = probe_wasix_worker(
        &WasixWorkerConfig::new(wrong_binary).with_handshake_timeout(Duration::from_secs(1)),
    )
    .await
    .unwrap_err();
    assert!(matches!(wrong, Error::Execution(_)), "{wrong:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_symlinked_worker_paths() {
    let directory = tempfile::tempdir().unwrap();
    let link = directory.path().join("worker");
    std::os::unix::fs::symlink(WORKER, &link).unwrap();
    let error = probe_wasix_worker(&WasixWorkerConfig::new(link))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Configuration(_)));
}

#[tokio::test]
async fn rejects_unbounded_handshake_timeouts() {
    for timeout in [Duration::ZERO, Duration::from_secs(31)] {
        let error =
            probe_wasix_worker(&WasixWorkerConfig::new(WORKER).with_handshake_timeout(timeout))
                .await
                .unwrap_err();
        assert!(matches!(error, Error::Configuration(_)));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn timeout_and_cancellation_kill_the_complete_probe_process_group() {
    let (_directory, worker, worker_file, descendant_file) = forking_worker();
    let error = probe_wasix_worker(
        &WasixWorkerConfig::new(worker).with_handshake_timeout(Duration::from_millis(250)),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, Error::Timeout), "{error:?}");

    let worker_pid = wait_for_pid(&worker_file).await;
    let descendant = wait_for_pid(&descendant_file).await;
    wait_for_process_exit(worker_pid).await;
    wait_for_process_exit(descendant).await;

    let (_directory, worker, worker_file, descendant_file) = forking_worker();
    let config = WasixWorkerConfig::new(worker).with_handshake_timeout(Duration::from_secs(10));
    let task = tokio::spawn(async move { probe_wasix_worker(&config).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!task.is_finished(), "probe exited before cancellation");
    let worker_pid = wait_for_pid(&worker_file).await;
    let descendant = wait_for_pid(&descendant_file).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    wait_for_process_exit(worker_pid).await;
    wait_for_process_exit(descendant).await;
}

#[cfg(unix)]
fn forking_worker() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let worker = directory.path().join("forking-worker");
    let worker_file = directory.path().join("worker.pid");
    let descendant_file = directory.path().join("descendant.pid");
    let mut executable = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&worker)
        .unwrap();
    write!(
        executable,
        "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{}'\n/bin/sleep 30 &\nprintf '%s\\n' \"$!\" > '{}'\nwait\n",
        worker_file.display(),
        descendant_file.display()
    )
    .unwrap();
    executable.sync_all().unwrap();
    drop(executable);
    std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    (directory, worker, worker_file, descendant_file)
}

#[cfg(unix)]
async fn wait_for_pid(path: &std::path::Path) -> rustix::process::Pid {
    for _ in 0..100 {
        if let Ok(value) = std::fs::read_to_string(path)
            && let Ok(raw) = value.trim().parse::<i32>()
            && let Some(pid) = rustix::process::Pid::from_raw(raw)
        {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("forking worker did not report a PID in {}", path.display());
}

#[cfg(unix)]
async fn wait_for_process_exit(pid: rustix::process::Pid) {
    for _ in 0..100 {
        if rustix::process::test_kill_process(pid).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("worker descendant {pid:?} survived process-group cleanup");
}

fn expected_worker_groups() -> Vec<u32> {
    if rustix::process::geteuid().is_root() {
        return Vec::new();
    }
    let mut groups: Vec<_> = rustix::process::getgroups()
        .unwrap()
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .collect();
    groups.sort_unstable();
    groups.dedup();
    groups
}

fn verified_transport_checkpoint() -> runtrue_wasm_runtime::VerifiedWasixCheckpoint {
    use hmac::{Hmac, Mac as _};

    type HmacSha256 = Hmac<Sha256>;
    let binding = WasixCheckpointBinding::new(
        format!("sha256:{}", "1".repeat(64)),
        "2".repeat(64),
        "_start",
        "transport-test",
        1,
    )
    .unwrap();
    // Framing-only test journal. The transport probe never deserializes these
    // synthetic record bodies with Wasmer/rkyv.
    let mut journal = 0x310d_6dd0_2736_2979_u64.to_be_bytes().to_vec();
    push_test_record(&mut journal, 1, &[0]);
    push_test_record(&mut journal, 3, &[0]);
    push_test_record(&mut journal, 59, &[0]);
    let metadata = serde_json::to_vec(&serde_json::json!({
        "binding": {
            "environmentId": binding.environment_id(),
            "moduleSha256": binding.module_sha256(),
            "command": binding.command(),
            "instanceId": binding.instance_id(),
            "generation": binding.generation(),
        },
        "runtimeVersion": env!("CARGO_PKG_VERSION"),
        "workerProtocolVersion": WASIX_WORKER_PROTOCOL_VERSION,
        "cohortId": WASIX_COHORT_ID,
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
        "journalSha256": hex::encode(Sha256::digest(&journal)),
    }))
    .unwrap();
    let mut artifact = Vec::new();
    artifact.extend_from_slice(b"RTWCPKT\0");
    artifact.extend_from_slice(&1_u16.to_be_bytes());
    artifact.extend_from_slice(&u32::try_from(metadata.len()).unwrap().to_be_bytes());
    artifact.extend_from_slice(&u64::try_from(journal.len()).unwrap().to_be_bytes());
    artifact.extend_from_slice(&metadata);
    artifact.extend_from_slice(&journal);
    let mut mac = HmacSha256::new_from_slice(&[7; 32]).unwrap();
    mac.update(b"runtrue-wasm-runtime.wasix-checkpoint.v1\0");
    mac.update(&artifact);
    artifact.extend_from_slice(&mac.finalize().into_bytes());
    WasixCheckpointCodec::new(CheckpointAuthenticationKey::new([7; 32]))
        .with_max_journal_bytes(1024)
        .open(&binding, &artifact)
        .unwrap()
}

fn push_test_record(journal: &mut Vec<u8>, record_type: u16, body: &[u8]) {
    journal.extend_from_slice(&record_type.to_be_bytes());
    journal.extend_from_slice(&u64::try_from(body.len()).unwrap().to_be_bytes()[2..]);
    journal.extend_from_slice(body);
}

fn checkpoint_memfd(bytes: &[u8], seals: rustix::fs::SealFlags) -> std::fs::File {
    use rustix::fs::{MemfdFlags, fcntl_add_seals, memfd_create};
    use std::io::{SeekFrom, Write as _};

    let descriptor = memfd_create(
        "runtrue-wasix-checkpoint-test",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    let mut file = std::fs::File::from(descriptor);
    file.write_all(bytes).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    fcntl_add_seals(&file, seals).unwrap();
    file
}

async fn assert_transport_rejected(input: std::fs::File) {
    let (control, child_control) = checkpoint_control_channel();
    let mut child = tokio::process::Command::new(WORKER)
        .arg("--checkpoint-transport-probe")
        .env_clear()
        .current_dir("/")
        .stdin(child_control)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let ready = read_test_frame(&mut stdout).await;
    let metadata: runtrue_wasm_runtime::WasixWorkerMetadata =
        serde_json::from_slice(&ready).unwrap();
    assert_eq!(metadata.protocol_version, WASIX_WORKER_PROTOCOL_VERSION);
    send_checkpoint_descriptor(&control, &input);
    assert!(read_test_frame_result(&mut stdout).await.is_err());
    assert!(!child.wait().await.unwrap().success());
}

fn checkpoint_control_channel() -> (std::os::unix::net::UnixStream, Stdio) {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    let (parent, child) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    (
        std::os::unix::net::UnixStream::from(parent),
        Stdio::from(std::fs::File::from(child)),
    )
}

fn send_checkpoint_descriptor(
    control: &std::os::unix::net::UnixStream,
    checkpoint: &std::fs::File,
) {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    use std::{io::IoSlice, mem::MaybeUninit, os::fd::AsFd as _};

    let descriptors = [checkpoint.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    assert_eq!(
        sendmsg(
            control,
            &[IoSlice::new(b"C")],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .unwrap(),
        1
    );
}

async fn read_test_frame(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    read_test_frame_result(reader).await.unwrap()
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
