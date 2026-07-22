use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::oneshot,
};

/// Worker protocol implemented by this runtime release.
pub const WASIX_WORKER_PROTOCOL_VERSION: u32 = 1;

/// Exact engine and package cohort required for worker compatibility.
pub const WASIX_COHORT_ID: &str = "wasmer-7.1.0+wasix-0.701.0+webc-11.0.0";

const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Explicit deployment configuration for the out-of-process WASIX worker.
///
/// The executable is a deployment trust anchor and must be installed at a
/// trusted, administrator-controlled path. The protocol probe checks reported
/// compatibility; it is not a signature over the executable. Version 1 of the
/// worker process boundary is supported on Linux only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasixWorkerConfig {
    executable: PathBuf,
    handshake_timeout: Duration,
}

impl WasixWorkerConfig {
    /// Select an absolute worker executable path with a five-second handshake.
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            handshake_timeout: Duration::from_secs(5),
        }
    }

    /// Set the maximum time allowed for the complete deployment probe.
    #[must_use]
    pub const fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Configured worker executable.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Configured complete-handshake timeout.
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    fn validate(&self) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(Error::Configuration(
                "the WASIX worker process boundary currently requires Linux".to_owned(),
            ));
        }

        if !self.executable.is_absolute() {
            return Err(Error::Configuration(
                "WASIX worker executable must be an absolute path".to_owned(),
            ));
        }
        let metadata = fs::symlink_metadata(&self.executable).map_err(|error| {
            Error::Configuration(format!(
                "cannot inspect WASIX worker {}: {error}",
                self.executable.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::Configuration(format!(
                "WASIX worker must be a regular non-symlink file: {}",
                self.executable.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(Error::Configuration(format!(
                    "WASIX worker is not executable: {}",
                    self.executable.display()
                )));
            }
        }
        if self.handshake_timeout.is_zero() || self.handshake_timeout > MAX_HANDSHAKE_TIMEOUT {
            return Err(Error::Configuration(
                "WASIX worker handshake timeout must be between zero and 30 seconds".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Compatibility metadata reported by a successfully probed worker process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WasixWorkerMetadata {
    /// Framing and operation protocol version.
    pub protocol_version: u32,
    /// Runtime crate version used to build the worker.
    pub runtime_version: String,
    /// Exact Wasmer/WASIX/WebC dependency cohort.
    pub cohort_id: String,
    /// Operating-system process identifier of the fresh worker.
    pub process_id: u32,
}

impl WasixWorkerMetadata {
    fn current() -> Self {
        Self {
            protocol_version: WASIX_WORKER_PROTOCOL_VERSION,
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
            cohort_id: WASIX_COHORT_ID.to_owned(),
            process_id: std::process::id(),
        }
    }

    fn validate(&self, expected_process_id: u32) -> Result<()> {
        if self.protocol_version != WASIX_WORKER_PROTOCOL_VERSION {
            return Err(Error::UnsupportedComponent(format!(
                "WASIX worker protocol {} is incompatible with required protocol {}",
                self.protocol_version, WASIX_WORKER_PROTOCOL_VERSION
            )));
        }
        if self.runtime_version != env!("CARGO_PKG_VERSION") {
            return Err(Error::UnsupportedComponent(format!(
                "WASIX worker runtime {} is incompatible with required runtime {}",
                self.runtime_version,
                env!("CARGO_PKG_VERSION")
            )));
        }
        if self.cohort_id != WASIX_COHORT_ID {
            return Err(Error::UnsupportedComponent(format!(
                "WASIX worker cohort {:?} is incompatible with required cohort {WASIX_COHORT_ID:?}",
                self.cohort_id
            )));
        }
        if self.process_id != expected_process_id {
            return Err(Error::Execution(format!(
                "WASIX worker reported process {}, but spawned process was {expected_process_id}",
                self.process_id
            )));
        }
        Ok(())
    }
}

/// Spawn a fresh worker and check its framed protocol, build, cohort, and PID.
///
/// The probe performs no artifact parsing or compilation. It clears the
/// ambient environment, uses `/` as its working directory, and contains the
/// complete probe process tree in a fresh process group.
///
/// # Errors
///
/// Returns an error for an invalid deployment path, timeout, malformed frame,
/// nonzero worker exit, or any identity mismatch.
pub async fn probe_wasix_worker(config: &WasixWorkerConfig) -> Result<WasixWorkerMetadata> {
    config.validate()?;
    let mut command = Command::new(&config.executable);
    command
        .arg("--protocol-probe")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let child = command.spawn().map_err(|error| {
        Error::Execution(format!(
            "failed to spawn WASIX worker {}: {error}",
            config.executable.display()
        ))
    })?;
    let mut worker = WorkerProcess::new(child)?;
    let stdout = worker
        .child
        .stdout
        .take()
        .ok_or_else(|| Error::Execution("WASIX worker stdout was not piped".to_owned()))?;
    let (cancel, cancelled) = oneshot::channel();
    let supervisor = tokio::spawn(supervise_probe(
        worker,
        stdout,
        config.handshake_timeout,
        cancelled,
    ));
    ProbeSupervisor::new(supervisor, cancel).wait().await
}

async fn supervise_probe(
    mut worker: WorkerProcess,
    mut stdout: tokio::process::ChildStdout,
    handshake_timeout: Duration,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<WasixWorkerMetadata> {
    let process_id = worker.process_id;
    let outcome = tokio::select! {
        biased;
        _ = &mut cancelled => Err(Error::Cancelled),
        result = tokio::time::timeout(
            handshake_timeout,
            perform_handshake(&mut worker, &mut stdout, process_id),
        ) => match result {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout),
        },
    };

    if outcome.is_err() && worker.active {
        drop(stdout);
        spawn_worker_reaper(worker);
    }
    outcome
}

async fn perform_handshake(
    worker: &mut WorkerProcess,
    stdout: &mut tokio::process::ChildStdout,
    process_id: u32,
) -> Result<WasixWorkerMetadata> {
    let frame = read_frame(stdout).await?;
    let metadata: WasixWorkerMetadata = serde_json::from_slice(&frame)
        .map_err(|error| Error::Execution(format!("invalid WASIX worker ready frame: {error}")))?;
    metadata.validate(process_id)?;

    let mut trailing = [0_u8; 1];
    if stdout.read(&mut trailing).await.map_err(|error| {
        Error::Execution(format!("failed to finish WASIX worker handshake: {error}"))
    })? != 0
    {
        return Err(Error::Execution(
            "WASIX worker emitted trailing handshake bytes".to_owned(),
        ));
    }
    let status = worker.child.wait().await.map_err(|error| {
        Error::Execution(format!("failed to wait for WASIX worker probe: {error}"))
    })?;
    worker.kill_tree();
    worker.disarm();
    if !status.success() {
        return Err(Error::Execution(format!(
            "WASIX worker probe exited with {status}"
        )));
    }
    Ok(metadata)
}

struct ProbeSupervisor {
    task: tokio::task::JoinHandle<Result<WasixWorkerMetadata>>,
    cancel: Option<oneshot::Sender<()>>,
}

impl ProbeSupervisor {
    const fn new(
        task: tokio::task::JoinHandle<Result<WasixWorkerMetadata>>,
        cancel: oneshot::Sender<()>,
    ) -> Self {
        Self {
            task,
            cancel: Some(cancel),
        }
    }

    async fn wait(mut self) -> Result<WasixWorkerMetadata> {
        let outcome = (&mut self.task).await.map_err(|error| {
            Error::Execution(format!("WASIX worker supervisor failed: {error}"))
        })?;
        self.cancel.take();
        outcome
    }
}

impl Drop for ProbeSupervisor {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

struct WorkerProcess {
    child: tokio::process::Child,
    process_id: u32,
    active: bool,
}

impl WorkerProcess {
    fn new(child: tokio::process::Child) -> Result<Self> {
        let process_id = child.id().ok_or_else(|| {
            Error::Execution("WASIX worker did not expose a process identifier".to_owned())
        })?;
        Ok(Self {
            child,
            process_id,
            active: true,
        })
    }

    fn kill_tree(&mut self) {
        if !self.active {
            return;
        }
        #[cfg(unix)]
        if let Some(group) = rustix::process::Pid::from_raw(self.process_id.cast_signed()) {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

fn spawn_worker_reaper(mut worker: WorkerProcess) {
    worker.kill_tree();
    let _ = worker.child.start_kill();
    tokio::spawn(async move {
        let _ = worker.child.wait().await;
        worker.disarm();
    });
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.kill_tree();
        if self.active {
            let _ = self.child.start_kill();
        }
    }
}

async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await.map_err(|error| {
        Error::Execution(format!("failed to read WASIX worker frame length: {error}"))
    })?;
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length == 0 || length > MAX_HANDSHAKE_BYTES {
        return Err(Error::Execution(format!(
            "WASIX worker frame length {length} is invalid"
        )));
    }
    let mut frame = vec![0_u8; length];
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|error| Error::Execution(format!("failed to read WASIX worker frame: {error}")))?;
    Ok(frame)
}

/// Write the current worker metadata as one version 1 length-prefixed frame.
#[doc(hidden)]
pub fn write_wasix_worker_probe(mut writer: impl Write) -> std::result::Result<(), String> {
    let frame = serde_json::to_vec(&WasixWorkerMetadata::current())
        .map_err(|error| format!("cannot encode worker metadata: {error}"))?;
    if frame.len() > MAX_HANDSHAKE_BYTES {
        return Err("worker metadata exceeds the protocol frame limit".to_owned());
    }
    let length = u32::try_from(frame.len())
        .map_err(|_| "worker metadata exceeds the protocol frame limit".to_owned())?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(&frame))
        .and_then(|()| writer.flush())
        .map_err(|error| format!("cannot write worker metadata: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn rejects_each_worker_compatibility_mismatch() {
        let process_id = std::process::id();

        let mut metadata = WasixWorkerMetadata::current();
        metadata.protocol_version += 1;
        assert!(matches!(
            metadata.validate(process_id),
            Err(Error::UnsupportedComponent(_))
        ));

        let mut metadata = WasixWorkerMetadata::current();
        metadata.runtime_version.push_str("-other");
        assert!(matches!(
            metadata.validate(process_id),
            Err(Error::UnsupportedComponent(_))
        ));

        let mut metadata = WasixWorkerMetadata::current();
        metadata.cohort_id.push_str("-other");
        assert!(matches!(
            metadata.validate(process_id),
            Err(Error::UnsupportedComponent(_))
        ));

        let mut metadata = WasixWorkerMetadata::current();
        metadata.process_id = process_id.saturating_add(1);
        assert!(matches!(
            metadata.validate(process_id),
            Err(Error::Execution(_))
        ));
    }

    #[tokio::test]
    async fn rejects_zero_oversized_and_truncated_frames() {
        for bytes in [
            0_u32.to_be_bytes().to_vec(),
            u32::try_from(MAX_HANDSHAKE_BYTES + 1)
                .unwrap()
                .to_be_bytes()
                .to_vec(),
            [5_u32.to_be_bytes().as_slice(), b"no"].concat(),
        ] {
            let (mut writer, mut reader) = tokio::io::duplex(32);
            writer.write_all(&bytes).await.unwrap();
            drop(writer);
            assert!(matches!(
                read_frame(&mut reader).await,
                Err(Error::Execution(_))
            ));
        }
    }
}
