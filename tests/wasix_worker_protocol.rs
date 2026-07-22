//! WASIX worker deployment protocol integration tests.

#![cfg(all(feature = "wasix", target_os = "linux"))]

use runtrue_wasm_runtime::{
    Error, WASIX_COHORT_ID, WASIX_WORKER_PROTOCOL_VERSION, WasixWorkerConfig, probe_wasix_worker,
};
use std::time::Duration;

const WORKER: &str = env!("CARGO_BIN_EXE_runtrue-wasix-worker");

#[tokio::test]
async fn validates_the_explicit_worker_build_and_fresh_process() {
    let metadata = probe_wasix_worker(&WasixWorkerConfig::new(WORKER))
        .await
        .unwrap();
    assert_eq!(metadata.protocol_version, WASIX_WORKER_PROTOCOL_VERSION);
    assert_eq!(metadata.runtime_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(metadata.cohort_id, WASIX_COHORT_ID);
    assert_ne!(metadata.process_id, std::process::id());
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
