//! End-to-end source-worker capture of an authenticated WASIX checkpoint.

#![cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]

use std::{io::Write as _, net::Shutdown, process::Stdio, time::Duration};

use runtrue_wasm_runtime::{
    CheckpointAuthenticationKey, CommandInput, Error, WASIX_WORKER_PROTOCOL_VERSION,
    WasixCheckpointBinding, WasixCheckpointCodec, WasixWorkerConfig, capture_wasix_checkpoint,
};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt as _;

const FIXTURE: &[u8] = include_bytes!("fixtures/wasix-checkpoint-number.wasm");
const VALUE: &str = "424242";
const WORKER: &str = env!("CARGO_BIN_EXE_runtrue-wasix-worker");

#[tokio::test]
async fn captures_a_real_checkpoint_in_a_fresh_worker() {
    let module_sha256 = hex::encode(Sha256::digest(FIXTURE));
    let binding = checkpoint_binding(module_sha256.clone());
    let capture = capture_wasix_checkpoint(
        &worker_config(),
        binding.clone(),
        FIXTURE.to_vec(),
        CommandInput::default().with_args([VALUE]),
    )
    .await
    .expect("source worker must capture the explicit checkpoint");

    assert_eq!(capture.binding, binding);
    assert!(capture.stdout.is_empty(), "source must stop before stdout");
    assert!(capture.stderr.is_empty(), "source must not emit stderr");
    assert_eq!(capture.module_sha256, module_sha256);
    assert!(!capture.journal().is_empty());
    assert_eq!(
        capture.worker.protocol_version,
        WASIX_WORKER_PROTOCOL_VERSION
    );
    assert_ne!(capture.worker.process_id, std::process::id());
    assert!(capture.worker.isolation.no_new_privileges);
    assert_eq!(capture.worker.isolation.capability_masks, [0; 4]);

    let codec = WasixCheckpointCodec::new(CheckpointAuthenticationKey::new([7; 32]));
    let relabeled = [
        WasixCheckpointBinding::new(
            format!("sha256:{}", "2".repeat(64)),
            binding.module_sha256(),
            binding.command(),
            binding.instance_id(),
            binding.generation(),
        )
        .expect("environment relabel must be canonical"),
        WasixCheckpointBinding::new(
            binding.environment_id(),
            binding.module_sha256(),
            "other-command",
            binding.instance_id(),
            binding.generation(),
        )
        .expect("command relabel must be canonical"),
        WasixCheckpointBinding::new(
            binding.environment_id(),
            binding.module_sha256(),
            binding.command(),
            "other-instance",
            binding.generation(),
        )
        .expect("instance relabel must be canonical"),
        WasixCheckpointBinding::new(
            binding.environment_id(),
            binding.module_sha256(),
            binding.command(),
            binding.instance_id(),
            binding.generation() + 1,
        )
        .expect("generation relabel must be canonical"),
    ];
    for relabeled_binding in relabeled {
        let error = codec
            .seal(&relabeled_binding, capture.journal())
            .expect_err("an attested capture must not be relabeled during sealing");
        assert!(
            matches!(error, Error::Checkpoint(message) if message == "captured journal binding does not match the checkpoint binding")
        );
    }

    let artifact = codec
        .seal_capture(capture.journal())
        .expect("trusted worker capture must seal");
    let verified = codec
        .open(&binding, &artifact)
        .expect("sealed worker capture must authenticate and reopen");
    assert_eq!(verified.binding(), &binding);
    assert_eq!(verified.journal().len(), capture.journal().len());
    assert_eq!(
        hex::encode(Sha256::digest(verified.journal())),
        capture.journal_sha256
    );
}

#[tokio::test]
async fn rejects_a_module_that_does_not_match_the_binding() {
    let binding = checkpoint_binding("0".repeat(64));
    let error = capture_wasix_checkpoint(
        &worker_config(),
        binding,
        FIXTURE.to_vec(),
        CommandInput::default().with_args([VALUE]),
    )
    .await
    .expect_err("capture must reject a module outside its authenticated binding");

    assert!(matches!(error, Error::Checkpoint(_)), "{error:?}");
}

#[tokio::test]
async fn capture_waits_for_execute_authorization() {
    let module = sealed_capture_input(FIXTURE);
    let request = serde_json::to_vec(&serde_json::json!({
        "arguments": [VALUE],
        "environment": {},
    }))
    .expect("capture request must encode");
    let (mut control, child_control) = capture_control_channel();
    let mut child = tokio::process::Command::new(WORKER)
        .arg("--checkpoint-capture")
        .env_clear()
        .current_dir("/")
        .stdin(child_control)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("capture worker must spawn");
    let mut stdout = child.stdout.take().expect("worker stdout must be piped");

    let ready: runtrue_wasm_runtime::WasixWorkerMetadata =
        serde_json::from_slice(&read_test_frame(&mut stdout).await)
            .expect("worker Ready frame must decode");
    assert_eq!(ready.protocol_version, WASIX_WORKER_PROTOCOL_VERSION);
    assert_ne!(ready.process_id, std::process::id());

    send_capture_descriptor(&control, &module);
    control
        .write_all(
            &u32::try_from(request.len())
                .expect("capture request length must fit u32")
                .to_be_bytes(),
        )
        .expect("capture request length must be writable");
    control
        .write_all(&request)
        .expect("capture request must be writable");
    let acknowledgement: serde_json::Value =
        serde_json::from_slice(&read_test_frame(&mut stdout).await)
            .expect("capture acknowledgement must decode");
    assert_eq!(acknowledgement["moduleBytes"], FIXTURE.len());
    assert_eq!(
        acknowledgement["moduleSha256"],
        hex::encode(Sha256::digest(FIXTURE))
    );
    assert_eq!(acknowledgement["requestBytes"], request.len());
    assert_eq!(
        acknowledgement["requestSha256"],
        hex::encode(Sha256::digest(&request))
    );

    match tokio::time::timeout(
        Duration::from_millis(100),
        read_test_frame_result(&mut stdout),
    )
    .await
    {
        Err(_) => {}
        Ok(Ok(frame)) => {
            panic!("capture worker emitted a completion before Execute authorization: {frame:?}")
        }
        Ok(Err(error)) => {
            panic!("capture worker exited before Execute authorization instead of waiting: {error}")
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
        .expect("capture completion must decode");
    let journal = read_test_frame(&mut stdout).await;
    let captured_stdout = read_test_frame(&mut stdout).await;
    let captured_stderr = read_test_frame(&mut stdout).await;
    assert_eq!(completion["exitCode"], 0);
    assert_frame_metadata(&completion, "journal", &journal);
    assert_frame_metadata(&completion, "stdout", &captured_stdout);
    assert_frame_metadata(&completion, "stderr", &captured_stderr);
    assert!(!journal.is_empty());
    assert!(captured_stdout.is_empty());
    assert!(captured_stderr.is_empty());

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
            .expect("capture worker must be waitable")
            .success()
    );
}

fn checkpoint_binding(module_sha256: String) -> WasixCheckpointBinding {
    WasixCheckpointBinding::new(
        format!("sha256:{}", "1".repeat(64)),
        module_sha256,
        "_start",
        "source-capture-test",
        1,
    )
    .expect("fixture binding must be valid")
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

fn assert_frame_metadata(completion: &serde_json::Value, label: &str, frame: &[u8]) {
    let bytes_field = format!("{label}Bytes");
    let digest_field = format!("{label}Sha256");
    assert_eq!(completion[bytes_field], frame.len());
    assert_eq!(completion[digest_field], hex::encode(Sha256::digest(frame)));
}

fn sealed_capture_input(bytes: &[u8]) -> std::fs::File {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

    let descriptor = memfd_create(
        "runtrue-wasix-capture-test",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .expect("capture memfd must be creatable");
    let mut file = std::fs::File::from(descriptor);
    file.write_all(bytes)
        .expect("capture memfd must be writable before sealing");
    fcntl_add_seals(
        &file,
        SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
    )
    .expect("capture memfd must accept all required seals");
    file
}

fn capture_control_channel() -> (std::os::unix::net::UnixStream, Stdio) {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    let (parent, child) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("capture control socketpair must be creatable");
    (
        std::os::unix::net::UnixStream::from(parent),
        Stdio::from(std::fs::File::from(child)),
    )
}

fn send_capture_descriptor(control: &std::os::unix::net::UnixStream, module: &std::fs::File) {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    use std::{io::IoSlice, mem::MaybeUninit, os::fd::AsFd as _};

    let descriptors = [module.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
    assert_eq!(
        sendmsg(
            control,
            &[IoSlice::new(b"M")],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )
        .expect("capture module descriptor must be transferable"),
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
