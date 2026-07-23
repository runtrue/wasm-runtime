#[cfg(feature = "wasix-checkpoint")]
use crate::{CapturedWasixJournal, CommandInput};
use crate::{Error, Result, VerifiedWasixCheckpoint, WasixCheckpointBinding};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};
#[cfg(all(feature = "wasix", not(target_os = "linux")))]
use std::io::Read;
#[cfg(any(feature = "wasix", target_os = "linux"))]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::oneshot,
};

/// Worker protocol implemented by this runtime release.
pub const WASIX_WORKER_PROTOCOL_VERSION: u32 = 6;

/// Exact engine and package cohort required for worker compatibility.
pub const WASIX_COHORT_ID: &str = "wasmer-7.1.0+wasix-0.701.0+webc-11.0.0";

const WASIX_WORKER_ISOLATION_PROFILE_VERSION: u32 = 2;
const WASIX_WORKER_MAX_OPEN_FILES: u64 = 64;
const WASIX_WORKER_MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const WASIX_WORKER_MAX_ADDRESS_SPACE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const WASIX_WORKER_MAX_SUPPLEMENTARY_GROUPS: usize = 64;
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const WASIX_WORKER_MAX_CHECKPOINT_BYTES: usize = 512 * 1024 * 1024;
#[cfg(feature = "wasix-checkpoint")]
const WASIX_WORKER_MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
#[cfg(feature = "wasix-checkpoint")]
const WASIX_WORKER_MAX_RESTORE_OUTPUT_BYTES: usize = 64 * 1024;
#[cfg(feature = "wasix-checkpoint")]
const WASIX_WORKER_MAX_CAPTURE_REQUEST_BYTES: usize = 64 * 1024;
#[cfg(feature = "wasix-checkpoint")]
const WASIX_WORKER_MAX_CAPTURE_ARGUMENTS: usize = 256;
#[cfg(feature = "wasix-checkpoint")]
const WASIX_WORKER_MAX_CAPTURE_ENVIRONMENT: usize = 256;
#[cfg(feature = "wasix-checkpoint")]
const WASIX_WORKER_MAX_CAPTURE_VALUE_BYTES: usize = 4 * 1024;
#[cfg(target_os = "linux")]
const REQUIRED_CHECKPOINT_SEALS: rustix::fs::SealFlags = rustix::fs::SealFlags::SEAL
    .union(rustix::fs::SealFlags::SHRINK)
    .union(rustix::fs::SealFlags::GROW)
    .union(rustix::fs::SealFlags::WRITE);

/// Explicit deployment configuration for the out-of-process WASIX worker.
///
/// The executable is a deployment trust anchor and must be installed at a
/// trusted, administrator-controlled path. The protocol probe checks reported
/// compatibility; it is not a signature over the executable. Version 6 of the
/// worker process boundary is supported on Linux only.
#[derive(Clone)]
pub struct WasixWorkerConfig {
    executable: PathBuf,
    handshake_timeout: Duration,
    allowed_supplementary_groups: Vec<u32>,
    placement: Option<Arc<dyn WasixWorkerPlacement>>,
}

impl std::fmt::Debug for WasixWorkerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasixWorkerConfig")
            .field("executable", &self.executable)
            .field("handshake_timeout", &self.handshake_timeout)
            .field(
                "allowed_supplementary_groups",
                &self.allowed_supplementary_groups,
            )
            .field("placement_configured", &self.placement.is_some())
            .finish()
    }
}

impl PartialEq for WasixWorkerConfig {
    fn eq(&self, other: &Self) -> bool {
        self.executable == other.executable
            && self.handshake_timeout == other.handshake_timeout
            && self.allowed_supplementary_groups == other.allowed_supplementary_groups
            && match (&self.placement, &other.placement) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }
}

impl Eq for WasixWorkerConfig {}

/// Operation for which a fresh isolated WASIX worker was spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WasixWorkerOperation {
    /// Compatibility and isolation probe without guest input.
    Probe,
    /// Sealed checkpoint transport qualification.
    CheckpointTransport,
    /// Restore and resume an authenticated checkpoint.
    CheckpointRestore,
    /// Execute a source workload until its explicit checkpoint.
    CheckpointCapture,
}

/// Identity passed to a configured pre-input worker placement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasixWorkerPlacementRequest {
    process_id: u32,
    operation: WasixWorkerOperation,
}

impl WasixWorkerPlacementRequest {
    /// Operating-system process identifier of the newly spawned worker.
    #[must_use]
    pub const fn process_id(self) -> u32 {
        self.process_id
    }

    /// Worker operation that will run after placement succeeds.
    #[must_use]
    pub const fn operation(self) -> WasixWorkerOperation {
        self.operation
    }
}

/// Synchronous, fail-closed placement policy for newly spawned WASIX workers.
///
/// The callback runs immediately after spawn and before the parent sends module,
/// checkpoint, request, or Execute bytes. A deployment can use the PID to write
/// the worker into a pre-created cgroup v2 `cgroup.procs` file, then verify the
/// resulting membership before returning. Returning an error kills and reaps
/// the worker without authorizing guest execution.
///
/// Implementations must complete promptly and must not retain the PID for a
/// later asynchronous action. The child remains an unreaped child throughout
/// this callback, preventing its PID from being recycled during placement.
pub trait WasixWorkerPlacement: Send + Sync + 'static {
    /// Place and authorize one fresh worker before any workload input is sent.
    ///
    /// # Errors
    ///
    /// Returning an error rejects the worker and aborts the operation.
    fn place(&self, request: WasixWorkerPlacementRequest) -> Result<()>;
}

impl<F> WasixWorkerPlacement for F
where
    F: Fn(WasixWorkerPlacementRequest) -> Result<()> + Send + Sync + 'static,
{
    fn place(&self, request: WasixWorkerPlacementRequest) -> Result<()> {
        self(request)
    }
}

impl WasixWorkerConfig {
    /// Select an absolute worker executable path with a five-second handshake.
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            handshake_timeout: Duration::from_secs(5),
            allowed_supplementary_groups: Vec::new(),
            placement: None,
        }
    }

    /// Set the maximum time allowed for a complete probe, transport, or restore.
    ///
    /// Checkpoint transport applies this deadline to memfd preparation plus
    /// the complete Ready, acknowledgement, EOF, and worker-exit exchange.
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

    /// Allow an exact set of inherited non-root supplementary group IDs.
    ///
    /// The secure default is an empty set. Only add groups required by the
    /// dedicated worker service account; group zero is always rejected.
    #[must_use]
    pub fn with_allowed_supplementary_groups(
        mut self,
        groups: impl IntoIterator<Item = u32>,
    ) -> Self {
        self.allowed_supplementary_groups = groups.into_iter().collect();
        self.allowed_supplementary_groups.sort_unstable();
        self.allowed_supplementary_groups.dedup();
        self
    }

    /// Require a deployment placement policy before accepting worker input.
    ///
    /// The policy is invoked for every worker spawned by this configuration.
    /// Failure is fail-closed: the worker is killed and reaped, and no guest,
    /// module, checkpoint, request, or Execute bytes are sent. The default
    /// configuration has no policy and therefore makes no cgroup-placement
    /// claim; production deployments that require per-invocation cgroups must
    /// configure and verify them here.
    #[must_use]
    pub fn with_worker_placement(mut self, placement: impl WasixWorkerPlacement) -> Self {
        self.placement = Some(Arc::new(placement));
        self
    }

    /// Whether a fail-closed external placement policy is configured.
    #[must_use]
    pub fn has_worker_placement(&self) -> bool {
        self.placement.is_some()
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
            let mode = metadata.permissions().mode();
            if mode & 0o111 == 0 {
                return Err(Error::Configuration(format!(
                    "WASIX worker is not executable: {}",
                    self.executable.display()
                )));
            }
            if mode & 0o6000 != 0 {
                return Err(Error::Configuration(format!(
                    "WASIX worker must not be set-user-ID or set-group-ID: {}",
                    self.executable.display()
                )));
            }
        }
        #[cfg(target_os = "linux")]
        {
            let mut capabilities = [0_u8; 256];
            match rustix::fs::getxattr(&self.executable, "security.capability", &mut capabilities) {
                Ok(bytes) if bytes != 0 => {
                    return Err(Error::Configuration(format!(
                        "WASIX worker must not have file capabilities: {}",
                        self.executable.display()
                    )));
                }
                Ok(_) | Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP) => {}
                Err(error) => {
                    return Err(Error::Configuration(format!(
                        "cannot inspect WASIX worker file capabilities for {}: {error}",
                        self.executable.display()
                    )));
                }
            }
        }
        if self.handshake_timeout.is_zero() || self.handshake_timeout > MAX_HANDSHAKE_TIMEOUT {
            return Err(Error::Configuration(
                "WASIX worker handshake timeout must be between zero and 30 seconds".to_owned(),
            ));
        }
        if self.allowed_supplementary_groups.len() > WASIX_WORKER_MAX_SUPPLEMENTARY_GROUPS
            || self.allowed_supplementary_groups.contains(&0)
        {
            return Err(Error::Configuration(
                "WASIX worker supplementary group allowlist is invalid".to_owned(),
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
    /// Verified Linux isolation state established before this frame was written.
    pub isolation: WasixWorkerIsolation,
}

impl WasixWorkerMetadata {
    #[cfg(any(feature = "wasix", test))]
    fn current(isolation: WasixWorkerIsolation) -> Self {
        Self {
            protocol_version: WASIX_WORKER_PROTOCOL_VERSION,
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
            cohort_id: WASIX_COHORT_ID.to_owned(),
            process_id: std::process::id(),
            isolation,
        }
    }

    fn validate(&self, expected_process_id: u32, allowed_groups: &[u32]) -> Result<()> {
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
        self.isolation.validate(allowed_groups)?;
        Ok(())
    }
}

/// Result of transporting one verified checkpoint into a fresh isolated worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasixCheckpointTransportMetadata {
    /// Compatibility and isolation state reported before checkpoint input was read.
    pub worker: WasixWorkerMetadata,
    /// Authenticated workload and generation bound to the transported journal.
    pub binding: WasixCheckpointBinding,
    /// Exact number of immutable journal bytes accepted by the worker.
    pub journal_bytes: u64,
    /// Lowercase SHA-256 digest independently computed by the worker.
    pub journal_sha256: String,
}

/// Result of restoring an authenticated checkpoint in a fresh isolated worker.
#[cfg(feature = "wasix-checkpoint")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasixCheckpointRestoreMetadata {
    /// Compatibility and isolation state of the destination worker.
    pub worker: WasixWorkerMetadata,
    /// Authenticated workload and generation restored by the worker.
    pub binding: WasixCheckpointBinding,
    /// Bounded standard output emitted after the checkpoint resumed.
    pub stdout: Vec<u8>,
    /// Lowercase SHA-256 digest of the restored module.
    pub module_sha256: String,
    /// Lowercase SHA-256 digest of the restored journal.
    pub journal_sha256: String,
}

/// Trusted journal capture produced by a fresh isolated source worker.
#[cfg(feature = "wasix-checkpoint")]
pub struct WasixCheckpointCapture {
    /// Compatibility and isolation state of the source worker.
    pub worker: WasixWorkerMetadata,
    /// Workload identity to which the captured journal will be sealed.
    pub binding: WasixCheckpointBinding,
    /// Bounded output emitted before the explicit snapshot.
    pub stdout: Vec<u8>,
    /// Bounded error output emitted before the explicit snapshot.
    pub stderr: Vec<u8>,
    /// Lowercase SHA-256 digest of the executed module.
    pub module_sha256: String,
    /// Lowercase SHA-256 digest of the captured journal prefix.
    pub journal_sha256: String,
    journal: CapturedWasixJournal,
}

#[cfg(feature = "wasix-checkpoint")]
impl std::fmt::Debug for WasixCheckpointCapture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasixCheckpointCapture")
            .field("worker", &self.worker)
            .field("binding", &self.binding)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("module_sha256", &self.module_sha256)
            .field("journal_sha256", &self.journal_sha256)
            .field("journal", &self.journal)
            .finish()
    }
}

#[cfg(feature = "wasix-checkpoint")]
impl WasixCheckpointCapture {
    /// Attested journal that can be authenticated with [`crate::WasixCheckpointCodec`].
    #[must_use]
    pub const fn journal(&self) -> &CapturedWasixJournal {
        &self.journal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WasixCheckpointTransportAck {
    journal_bytes: u64,
    journal_sha256: String,
}

#[cfg(feature = "wasix-checkpoint")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WasixCheckpointRestoreAck {
    module_bytes: u64,
    module_sha256: String,
    journal_bytes: u64,
    journal_sha256: String,
}

#[cfg(feature = "wasix-checkpoint")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WasixCheckpointRestoreCompletion {
    exit_code: i32,
    stdout_bytes: u64,
    stdout_sha256: String,
}

#[cfg(feature = "wasix-checkpoint")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WasixCheckpointCaptureRequest {
    arguments: Vec<String>,
    environment: std::collections::BTreeMap<String, String>,
}

#[cfg(feature = "wasix-checkpoint")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WasixCheckpointCaptureAck {
    module_bytes: u64,
    module_sha256: String,
    request_bytes: u64,
    request_sha256: String,
}

#[cfg(feature = "wasix-checkpoint")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WasixCheckpointCaptureCompletion {
    exit_code: i32,
    journal_bytes: u64,
    journal_sha256: String,
    stdout_bytes: u64,
    stdout_sha256: String,
    stderr_bytes: u64,
    stderr_sha256: String,
}

impl WasixCheckpointTransportAck {
    fn validate(&self, expected_bytes: u64, expected_sha256: &str) -> Result<()> {
        if self.journal_bytes != expected_bytes || self.journal_sha256 != expected_sha256 {
            return Err(Error::Execution(
                "WASIX worker checkpoint acknowledgement did not match the sealed input".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "wasix-checkpoint")]
impl WasixCheckpointRestoreAck {
    fn validate(
        &self,
        module_bytes: u64,
        module_sha256: &str,
        journal_bytes: u64,
        journal_sha256: &str,
    ) -> Result<()> {
        if self.module_bytes != module_bytes
            || self.module_sha256 != module_sha256
            || self.journal_bytes != journal_bytes
            || self.journal_sha256 != journal_sha256
        {
            return Err(Error::Execution(
                "WASIX worker restore acknowledgement did not match the sealed inputs".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "wasix-checkpoint")]
impl WasixCheckpointRestoreCompletion {
    fn validate(&self, stdout: &[u8]) -> Result<()> {
        let stdout_bytes = u64::try_from(stdout.len())
            .map_err(|_| Error::Execution("WASIX worker output length overflows u64".to_owned()))?;
        let stdout_sha256 = hex::encode(Sha256::digest(stdout));
        if self.exit_code != 0
            || self.stdout_bytes != stdout_bytes
            || self.stdout_sha256 != stdout_sha256
        {
            return Err(Error::Execution(
                "WASIX worker restore completion did not match its output".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "wasix-checkpoint")]
impl WasixCheckpointCaptureRequest {
    fn new(input: CommandInput) -> Result<(Self, Duration, crate::CancellationToken)> {
        if !input.stdin.is_empty() {
            return Err(Error::Configuration(
                "WASIX checkpoint capture does not yet support standard input".to_owned(),
            ));
        }
        if input.timeout.is_zero() || input.timeout > MAX_HANDSHAKE_TIMEOUT {
            return Err(Error::Configuration(
                "WASIX checkpoint capture timeout must be between zero and 30 seconds".to_owned(),
            ));
        }
        let request = Self {
            arguments: input.args,
            environment: input.env,
        };
        request.validate().map_err(Error::Configuration)?;
        Ok((request, input.timeout, input.cancellation))
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.arguments.len() > WASIX_WORKER_MAX_CAPTURE_ARGUMENTS
            || self.environment.len() > WASIX_WORKER_MAX_CAPTURE_ENVIRONMENT
        {
            return Err("WASIX checkpoint capture input contains too many entries".to_owned());
        }
        for argument in &self.arguments {
            validate_capture_value("argument", argument, WASIX_WORKER_MAX_CAPTURE_VALUE_BYTES)?;
        }
        for (key, value) in &self.environment {
            if key.is_empty() || key.contains('=') {
                return Err("WASIX checkpoint capture environment key is invalid".to_owned());
            }
            validate_capture_value("environment key", key, 256)?;
            validate_capture_value(
                "environment value",
                value,
                WASIX_WORKER_MAX_CAPTURE_VALUE_BYTES,
            )?;
        }
        Ok(())
    }
}

#[cfg(feature = "wasix-checkpoint")]
fn validate_capture_value(
    label: &str,
    value: &str,
    maximum: usize,
) -> std::result::Result<(), String> {
    if value.len() > maximum || value.contains('\0') {
        return Err(format!("WASIX checkpoint capture {label} is invalid"));
    }
    Ok(())
}

#[cfg(feature = "wasix-checkpoint")]
impl WasixCheckpointCaptureCompletion {
    fn validate(&self, journal: &[u8], stdout: &[u8], stderr: &[u8]) -> Result<()> {
        let matches = |bytes: &[u8], expected_bytes: u64, expected_sha256: &str| {
            u64::try_from(bytes.len()).ok() == Some(expected_bytes)
                && hex::encode(Sha256::digest(bytes)) == expected_sha256
        };
        if self.exit_code != 0
            || !matches(journal, self.journal_bytes, &self.journal_sha256)
            || !matches(stdout, self.stdout_bytes, &self.stdout_sha256)
            || !matches(stderr, self.stderr_bytes, &self.stderr_sha256)
        {
            return Err(Error::Execution(
                "WASIX worker capture completion did not match its output".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Worker isolation postconditions established before accepting guest input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WasixWorkerIsolation {
    /// Version of the worker's operating-system isolation profile.
    pub profile_version: u32,
    /// Real, effective, saved, and filesystem Linux user IDs, in that order.
    pub user_ids: [u32; 4],
    /// Real, effective, saved, and filesystem Linux group IDs, in that order.
    pub group_ids: [u32; 4],
    /// Sorted supplementary group IDs retained by the worker.
    pub supplementary_group_ids: Vec<u32>,
    /// Whether supplementary group zero is present.
    pub has_root_supplementary_group: bool,
    /// Verified state of Linux's irreversible no-new-privileges bit.
    pub no_new_privileges: bool,
    /// Whether tracing and core-dump access is enabled.
    pub dumpable: bool,
    /// Effective, permitted, inheritable, and ambient capability masks.
    pub capability_masks: [u64; 4],
    /// Effective and hard core-file limits, in bytes.
    pub core_file_limits: [u64; 2],
    /// Effective and hard per-file size limits, in bytes.
    pub file_size_limits: [u64; 2],
    /// Effective and hard virtual-address-space limits, in bytes.
    pub address_space_limits: [u64; 2],
    /// Effective and hard open-file descriptor limits.
    pub open_file_limits: [u64; 2],
    /// Number of inherited descriptors at or above three closed before Ready.
    pub closed_inherited_descriptor_count: u32,
}

impl WasixWorkerIsolation {
    fn validate(&self, allowed_groups: &[u32]) -> Result<()> {
        if self.profile_version != WASIX_WORKER_ISOLATION_PROFILE_VERSION {
            return Err(Error::UnsupportedComponent(format!(
                "WASIX worker isolation profile {} is incompatible with required profile {WASIX_WORKER_ISOLATION_PROFILE_VERSION}",
                self.profile_version
            )));
        }
        if self.user_ids.contains(&0) || self.group_ids.contains(&0) {
            return Err(Error::Execution(
                "WASIX worker retained a root user or group credential".to_owned(),
            ));
        }
        if self.user_ids[3] != self.user_ids[1] || self.group_ids[3] != self.group_ids[1] {
            return Err(Error::Execution(
                "WASIX worker filesystem credentials differ from its effective identity".to_owned(),
            ));
        }
        if self.has_root_supplementary_group {
            return Err(Error::Execution(
                "WASIX worker retained supplementary group zero".to_owned(),
            ));
        }
        if self.supplementary_group_ids.len() > WASIX_WORKER_MAX_SUPPLEMENTARY_GROUPS
            || self.supplementary_group_ids != allowed_groups
        {
            return Err(Error::Execution(format!(
                "WASIX worker supplementary groups {:?} do not match the deployment allowlist",
                self.supplementary_group_ids
            )));
        }
        if !self.no_new_privileges || self.dumpable {
            return Err(Error::Execution(
                "WASIX worker did not seal privilege escalation and tracing".to_owned(),
            ));
        }
        if self.capability_masks != [0; 4] {
            return Err(Error::Execution(
                "WASIX worker retained Linux capabilities".to_owned(),
            ));
        }
        if self.core_file_limits != [0, 0] {
            return Err(Error::Execution(
                "WASIX worker did not disable core files".to_owned(),
            ));
        }
        let [file_size, hard_file_size] = self.file_size_limits;
        if file_size != hard_file_size || file_size == 0 || file_size > WASIX_WORKER_MAX_FILE_BYTES
        {
            return Err(Error::Execution(format!(
                "WASIX worker file-size limits {:?} exceed the isolation profile",
                self.file_size_limits
            )));
        }
        let [address_space, hard_address_space] = self.address_space_limits;
        if address_space != hard_address_space
            || address_space == 0
            || address_space > WASIX_WORKER_MAX_ADDRESS_SPACE_BYTES
        {
            return Err(Error::Execution(format!(
                "WASIX worker address-space limits {:?} exceed the isolation profile",
                self.address_space_limits
            )));
        }
        let [open_files, hard_open_files] = self.open_file_limits;
        if open_files != hard_open_files
            || open_files == 0
            || open_files > WASIX_WORKER_MAX_OPEN_FILES
        {
            return Err(Error::Execution(format!(
                "WASIX worker open-file limits {:?} exceed the isolation profile",
                self.open_file_limits
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    const fn compatible_for_test() -> Self {
        Self {
            profile_version: WASIX_WORKER_ISOLATION_PROFILE_VERSION,
            user_ids: [65_534; 4],
            group_ids: [65_534; 4],
            supplementary_group_ids: Vec::new(),
            has_root_supplementary_group: false,
            no_new_privileges: true,
            dumpable: false,
            capability_masks: [0; 4],
            core_file_limits: [0; 2],
            file_size_limits: [WASIX_WORKER_MAX_FILE_BYTES; 2],
            address_space_limits: [WASIX_WORKER_MAX_ADDRESS_SPACE_BYTES; 2],
            open_file_limits: [WASIX_WORKER_MAX_OPEN_FILES; 2],
            closed_inherited_descriptor_count: 0,
        }
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
    let mut worker = spawn_wasix_worker(config, WasixWorkerOperation::Probe, &mut command).await?;
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
        config.allowed_supplementary_groups.clone(),
        cancelled,
    ));
    ProbeSupervisor::new(supervisor, cancel).wait().await
}

/// Transport authenticated checkpoint journal bytes into a fresh isolated worker.
///
/// The journal is copied into an anonymous file and sealed against writes and
/// resizing. The child initially receives only a Unix control socket. After
/// the parent validates the isolated worker's Ready frame, it transfers the
/// sealed descriptor with `SCM_RIGHTS`; the worker validates its seals and size
/// before streaming the bytes into SHA-256. This operation deliberately
/// performs no Wasmer journal deserialization.
///
/// # Errors
///
/// Returns an error for invalid deployment configuration, an empty or
/// oversized journal, memfd or seal failures, timeout, cancellation, malformed
/// worker frames, or a digest/length mismatch.
pub async fn probe_wasix_checkpoint_transport(
    config: &WasixWorkerConfig,
    checkpoint: VerifiedWasixCheckpoint,
) -> Result<WasixCheckpointTransportMetadata> {
    config.validate()?;
    #[cfg(target_os = "linux")]
    {
        probe_wasix_checkpoint_transport_linux(config, checkpoint).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = checkpoint;
        Err(Error::Configuration(
            "the WASIX checkpoint transport currently requires Linux".to_owned(),
        ))
    }
}

/// Restore an authenticated WASIX checkpoint in a fresh isolated worker.
///
/// The destination receives the exact module and journal as fully sealed
/// anonymous files. It independently checks both digests and acknowledges
/// them before the parent authorizes execution. Destination arguments are
/// deliberately absent: process state, including the source arguments, is
/// recovered only from the authenticated journal.
///
/// # Errors
///
/// Returns an error for an incompatible binding, invalid deployment, input
/// preparation failure, timeout, worker protocol violation, restore failure,
/// or output beyond the fixed capture limit.
#[cfg(feature = "wasix-checkpoint")]
pub async fn restore_wasix_checkpoint(
    config: &WasixWorkerConfig,
    checkpoint: VerifiedWasixCheckpoint,
    module: Vec<u8>,
) -> Result<WasixCheckpointRestoreMetadata> {
    config.validate()?;
    #[cfg(target_os = "linux")]
    {
        restore_wasix_checkpoint_linux(config, checkpoint, module).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (checkpoint, module);
        Err(Error::Configuration(
            "WASIX checkpoint restore currently requires Linux".to_owned(),
        ))
    }
}

/// Capture an explicit WASIX snapshot in a fresh isolated source worker.
///
/// Authentication remains a parent concern: this returns a non-forgeable
/// journal that callers can pass to [`crate::WasixCheckpointCodec::seal`].
/// Standard input is rejected in this first capture protocol revision.
///
/// # Errors
///
/// Returns an error for invalid input or binding, timeout, cancellation,
/// worker protocol failure, a missing explicit snapshot, or bounded-output
/// overflow.
#[cfg(feature = "wasix-checkpoint")]
pub async fn capture_wasix_checkpoint(
    config: &WasixWorkerConfig,
    binding: WasixCheckpointBinding,
    module: Vec<u8>,
    input: CommandInput,
) -> Result<WasixCheckpointCapture> {
    config.validate()?;
    let (request, execution_timeout, cancellation) = WasixCheckpointCaptureRequest::new(input)?;
    if cancellation.is_cancelled() {
        return Err(Error::Cancelled);
    }
    #[cfg(target_os = "linux")]
    {
        capture_wasix_checkpoint_linux(
            config,
            binding,
            module,
            request,
            execution_timeout,
            cancellation,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (binding, module, request, execution_timeout, cancellation);
        Err(Error::Configuration(
            "WASIX checkpoint capture currently requires Linux".to_owned(),
        ))
    }
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
async fn capture_wasix_checkpoint_linux(
    config: &WasixWorkerConfig,
    binding: WasixCheckpointBinding,
    module: Vec<u8>,
    request: WasixCheckpointCaptureRequest,
    execution_timeout: Duration,
    cancellation: crate::CancellationToken,
) -> Result<WasixCheckpointCapture> {
    if binding.command() != "_start" {
        return Err(Error::UnsupportedComponent(
            "WASIX checkpoint capture supports only the \"_start\" command".to_owned(),
        ));
    }
    if module.is_empty() || module.len() > WASIX_WORKER_MAX_MODULE_BYTES {
        return Err(Error::Checkpoint(
            "WASIX capture module exceeds the worker input limit".to_owned(),
        ));
    }
    let request = serde_json::to_vec(&request).map_err(|error| {
        Error::Configuration(format!("capture request encoding failed: {error}"))
    })?;
    if request.is_empty() || request.len() > WASIX_WORKER_MAX_CAPTURE_REQUEST_BYTES {
        return Err(Error::Configuration(
            "WASIX checkpoint capture request exceeds the protocol limit".to_owned(),
        ));
    }
    let request_bytes = u64::try_from(request.len())
        .map_err(|_| Error::Configuration("capture request length overflows u64".to_owned()))?;
    let request_sha256 = hex::encode(Sha256::digest(&request));
    let deadline = tokio::time::Instant::now() + config.handshake_timeout;
    let preparation = ModulePreparation::new(module);
    let prepared_module = tokio::select! {
        () = cancellation.cancelled() => return Err(Error::Cancelled),
        result = preparation.wait(config.handshake_timeout) => result?,
    };
    if prepared_module.sha256 != binding.module_sha256() {
        return Err(Error::Checkpoint(
            "WASIX capture module does not match the checkpoint binding".to_owned(),
        ));
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(Error::Timeout);
    }

    let (control, child_control) = checkpoint_control_channel()?;
    let mut command = Command::new(&config.executable);
    command
        .arg("--checkpoint-capture")
        .env_clear()
        .current_dir("/")
        .stdin(child_control)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut worker = spawn_wasix_worker(
        config,
        WasixWorkerOperation::CheckpointCapture,
        &mut command,
    )
    .await?;
    drop(command);
    let stdout =
        worker.child.stdout.take().ok_or_else(|| {
            Error::Execution("WASIX capture worker stdout was not piped".to_owned())
        })?;
    let expected = ExpectedCheckpointCapture {
        binding,
        module_bytes: prepared_module.bytes,
        module_sha256: prepared_module.sha256,
        request_bytes,
        request_sha256,
    };
    let capture_input = CheckpointCaptureInput {
        control: Some(control),
        module: Some(prepared_module.file),
        request,
        expected,
    };
    let (cancel, cancelled) = oneshot::channel();
    let operation = CheckpointCaptureOperation {
        handshake_timeout: remaining,
        execution_timeout,
        allowed_supplementary_groups: config.allowed_supplementary_groups.clone(),
        input: capture_input,
        cancellation,
    };
    let supervisor = tokio::spawn(supervise_checkpoint_capture(
        worker, stdout, operation, cancelled,
    ));
    CheckpointCaptureSupervisor::new(supervisor, cancel)
        .wait()
        .await
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
async fn restore_wasix_checkpoint_linux(
    config: &WasixWorkerConfig,
    checkpoint: VerifiedWasixCheckpoint,
    module: Vec<u8>,
) -> Result<WasixCheckpointRestoreMetadata> {
    let binding = checkpoint.binding().clone();
    if binding.command() != "_start" {
        return Err(Error::UnsupportedComponent(format!(
            "WASIX checkpoint command {:?} cannot be restored; only \"_start\" is supported",
            binding.command()
        )));
    }
    if module.is_empty() || module.len() > WASIX_WORKER_MAX_MODULE_BYTES {
        return Err(Error::Checkpoint(
            "WASIX restore module exceeds the worker input limit".to_owned(),
        ));
    }
    let journal = checkpoint.into_journal();
    if journal.is_empty() || journal.len() > WASIX_WORKER_MAX_CHECKPOINT_BYTES {
        return Err(Error::Checkpoint(
            "verified checkpoint journal exceeds the worker restore limit".to_owned(),
        ));
    }

    let deadline = tokio::time::Instant::now() + config.handshake_timeout;
    let prepared_module = ModulePreparation::new(module)
        .wait(config.handshake_timeout)
        .await?;
    if prepared_module.sha256 != binding.module_sha256() {
        return Err(Error::Checkpoint(
            "WASIX restore module does not match the authenticated checkpoint binding".to_owned(),
        ));
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(Error::Timeout);
    }
    let prepared_checkpoint = CheckpointPreparation::new(journal).wait(remaining).await?;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(Error::Timeout);
    }

    let (control, child_control) = checkpoint_control_channel()?;
    let mut command = Command::new(&config.executable);
    command
        .arg("--checkpoint-restore")
        .env_clear()
        .current_dir("/")
        .stdin(child_control)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut worker = spawn_wasix_worker(
        config,
        WasixWorkerOperation::CheckpointRestore,
        &mut command,
    )
    .await?;
    drop(command);
    let stdout =
        worker.child.stdout.take().ok_or_else(|| {
            Error::Execution("WASIX restore worker stdout was not piped".to_owned())
        })?;
    let expected = ExpectedCheckpointRestore {
        binding,
        module_bytes: prepared_module.bytes,
        module_sha256: prepared_module.sha256,
        journal_bytes: prepared_checkpoint.journal_bytes,
        journal_sha256: prepared_checkpoint.journal_sha256,
    };
    let input = CheckpointRestoreInput {
        control: Some(control),
        module: Some(prepared_module.file),
        journal: Some(prepared_checkpoint.file),
        expected,
    };
    let (cancel, cancelled) = oneshot::channel();
    let supervisor = tokio::spawn(supervise_checkpoint_restore(
        worker,
        stdout,
        remaining,
        config.allowed_supplementary_groups.clone(),
        input,
        cancelled,
    ));
    CheckpointRestoreSupervisor::new(supervisor, cancel)
        .wait()
        .await
}

#[cfg(target_os = "linux")]
async fn probe_wasix_checkpoint_transport_linux(
    config: &WasixWorkerConfig,
    checkpoint: VerifiedWasixCheckpoint,
) -> Result<WasixCheckpointTransportMetadata> {
    let binding = checkpoint.binding().clone();
    let journal = checkpoint.into_journal();
    if journal.is_empty() || journal.len() > WASIX_WORKER_MAX_CHECKPOINT_BYTES {
        return Err(Error::Checkpoint(
            "verified checkpoint journal exceeds the worker transport limit".to_owned(),
        ));
    }
    let deadline = tokio::time::Instant::now() + config.handshake_timeout;
    let prepared = CheckpointPreparation::new(journal)
        .wait(config.handshake_timeout)
        .await?;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(Error::Timeout);
    }
    let (control, child_control) = checkpoint_control_channel()?;

    let mut command = Command::new(&config.executable);
    command
        .arg("--checkpoint-transport-probe")
        .env_clear()
        .current_dir("/")
        .stdin(child_control)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut worker = spawn_wasix_worker(
        config,
        WasixWorkerOperation::CheckpointTransport,
        &mut command,
    )
    .await?;
    drop(command);
    let stdout = worker
        .child
        .stdout
        .take()
        .ok_or_else(|| Error::Execution("WASIX worker stdout was not piped".to_owned()))?;
    let (cancel, cancelled) = oneshot::channel();
    let expected = ExpectedCheckpointTransport {
        binding,
        journal_bytes: prepared.journal_bytes,
        journal_sha256: prepared.journal_sha256,
    };
    let input = CheckpointTransportInput {
        control: Some(control),
        file: Some(prepared.file),
        expected,
    };
    let supervisor = tokio::spawn(supervise_checkpoint_transport(
        worker,
        stdout,
        remaining,
        config.allowed_supplementary_groups.clone(),
        input,
        cancelled,
    ));
    CheckpointTransportSupervisor::new(supervisor, cancel)
        .wait()
        .await
}

#[cfg(target_os = "linux")]
fn sealed_checkpoint_input(
    journal: Vec<u8>,
    cancelled: &AtomicBool,
) -> Result<PreparedCheckpointInput> {
    use rustix::fs::{FileType, MemfdFlags, fcntl_add_seals, fcntl_get_seals, fstat, memfd_create};

    let journal_bytes = u64::try_from(journal.len())
        .map_err(|_| Error::Checkpoint("checkpoint journal length overflows u64".to_owned()))?;
    let descriptor = memfd_create(
        "runtrue-wasix-checkpoint",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(|error| Error::Execution(format!("failed to create checkpoint memfd: {error}")))?;
    let mut file = std::fs::File::from(descriptor);
    let mut hash = Sha256::new();
    for chunk in journal.chunks(64 * 1024) {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        hash.update(chunk);
        file.write_all(chunk).map_err(|error| {
            Error::Execution(format!("failed to fill checkpoint memfd: {error}"))
        })?;
    }
    drop(journal);
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let journal_sha256 = hex::encode(hash.finalize());
    file.seek(SeekFrom::Start(0))
        .map_err(|error| Error::Execution(format!("failed to rewind checkpoint memfd: {error}")))?;
    fcntl_add_seals(&file, REQUIRED_CHECKPOINT_SEALS)
        .map_err(|error| Error::Execution(format!("failed to seal checkpoint memfd: {error}")))?;
    let installed = fcntl_get_seals(&file).map_err(|error| {
        Error::Execution(format!("failed to verify checkpoint memfd seals: {error}"))
    })?;
    if !installed.contains(REQUIRED_CHECKPOINT_SEALS) {
        return Err(Error::Execution(
            "checkpoint memfd is not fully sealed".to_owned(),
        ));
    }
    let stat = fstat(&file).map_err(|error| {
        Error::Execution(format!("failed to inspect checkpoint memfd: {error}"))
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 0
        || u64::try_from(stat.st_size).ok() != Some(journal_bytes)
    {
        return Err(Error::Execution(
            "checkpoint memfd identity is invalid".to_owned(),
        ));
    }
    Ok(PreparedCheckpointInput {
        file,
        journal_bytes,
        journal_sha256,
    })
}

#[cfg(target_os = "linux")]
struct PreparedCheckpointInput {
    file: std::fs::File,
    journal_bytes: u64,
    journal_sha256: String,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct PreparedModuleInput {
    file: std::fs::File,
    bytes: u64,
    sha256: String,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn sealed_module_input(module: Vec<u8>, cancelled: &AtomicBool) -> Result<PreparedModuleInput> {
    use rustix::fs::{FileType, MemfdFlags, fcntl_add_seals, fcntl_get_seals, fstat, memfd_create};

    let bytes = u64::try_from(module.len())
        .map_err(|_| Error::Checkpoint("WASIX module length overflows u64".to_owned()))?;
    let descriptor = memfd_create(
        "runtrue-wasix-module",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .map_err(|error| Error::Execution(format!("failed to create module memfd: {error}")))?;
    let mut file = std::fs::File::from(descriptor);
    let mut hash = Sha256::new();
    for chunk in module.chunks(64 * 1024) {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        hash.update(chunk);
        file.write_all(chunk)
            .map_err(|error| Error::Execution(format!("failed to fill module memfd: {error}")))?;
    }
    drop(module);
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let sha256 = hex::encode(hash.finalize());
    file.seek(SeekFrom::Start(0))
        .map_err(|error| Error::Execution(format!("failed to rewind module memfd: {error}")))?;
    fcntl_add_seals(&file, REQUIRED_CHECKPOINT_SEALS)
        .map_err(|error| Error::Execution(format!("failed to seal module memfd: {error}")))?;
    let installed = fcntl_get_seals(&file).map_err(|error| {
        Error::Execution(format!("failed to verify module memfd seals: {error}"))
    })?;
    let stat = fstat(&file)
        .map_err(|error| Error::Execution(format!("failed to inspect module memfd: {error}")))?;
    if !installed.contains(REQUIRED_CHECKPOINT_SEALS)
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 0
        || u64::try_from(stat.st_size).ok() != Some(bytes)
    {
        return Err(Error::Execution(
            "module memfd identity is invalid".to_owned(),
        ));
    }
    Ok(PreparedModuleInput {
        file,
        bytes,
        sha256,
    })
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct ModulePreparation {
    task: tokio::task::JoinHandle<Result<PreparedModuleInput>>,
    cancelled: Arc<AtomicBool>,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
impl ModulePreparation {
    fn new(module: Vec<u8>) -> Self {
        let cancelled = Arc::new(AtomicBool::new(false));
        let task_cancelled = Arc::clone(&cancelled);
        let task = tokio::task::spawn_blocking(move || {
            sealed_module_input(module, task_cancelled.as_ref())
        });
        Self { task, cancelled }
    }

    async fn wait(mut self, timeout: Duration) -> Result<PreparedModuleInput> {
        if let Ok(result) = tokio::time::timeout(timeout, &mut self.task).await {
            result.map_err(|error| {
                Error::Execution(format!("module memfd preparation failed to join: {error}"))
            })?
        } else {
            self.cancelled.store(true, Ordering::Relaxed);
            let _ = (&mut self.task).await;
            Err(Error::Timeout)
        }
    }
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
impl Drop for ModulePreparation {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.task.abort();
    }
}

#[cfg(target_os = "linux")]
struct CheckpointPreparation {
    task: tokio::task::JoinHandle<Result<PreparedCheckpointInput>>,
    cancelled: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
impl CheckpointPreparation {
    fn new(journal: Vec<u8>) -> Self {
        let cancelled = Arc::new(AtomicBool::new(false));
        let task_cancelled = Arc::clone(&cancelled);
        let task = tokio::task::spawn_blocking(move || {
            sealed_checkpoint_input(journal, task_cancelled.as_ref())
        });
        Self { task, cancelled }
    }

    async fn wait(mut self, timeout: Duration) -> Result<PreparedCheckpointInput> {
        if let Ok(result) = tokio::time::timeout(timeout, &mut self.task).await {
            result.map_err(|error| {
                Error::Execution(format!(
                    "checkpoint memfd preparation failed to join: {error}"
                ))
            })?
        } else {
            self.cancelled.store(true, Ordering::Relaxed);
            let _ = (&mut self.task).await;
            Err(Error::Timeout)
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for CheckpointPreparation {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.task.abort();
    }
}

#[cfg(target_os = "linux")]
struct ExpectedCheckpointTransport {
    binding: WasixCheckpointBinding,
    journal_bytes: u64,
    journal_sha256: String,
}

#[cfg(target_os = "linux")]
struct CheckpointTransportInput {
    control: Option<tokio::net::UnixStream>,
    file: Option<std::fs::File>,
    expected: ExpectedCheckpointTransport,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct ExpectedCheckpointRestore {
    binding: WasixCheckpointBinding,
    module_bytes: u64,
    module_sha256: String,
    journal_bytes: u64,
    journal_sha256: String,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct CheckpointRestoreInput {
    control: Option<tokio::net::UnixStream>,
    module: Option<std::fs::File>,
    journal: Option<std::fs::File>,
    expected: ExpectedCheckpointRestore,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct ExpectedCheckpointCapture {
    binding: WasixCheckpointBinding,
    module_bytes: u64,
    module_sha256: String,
    request_bytes: u64,
    request_sha256: String,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct CheckpointCaptureInput {
    control: Option<tokio::net::UnixStream>,
    module: Option<std::fs::File>,
    request: Vec<u8>,
    expected: ExpectedCheckpointCapture,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct CheckpointCaptureOperation {
    handshake_timeout: Duration,
    execution_timeout: Duration,
    allowed_supplementary_groups: Vec<u32>,
    input: CheckpointCaptureInput,
    cancellation: crate::CancellationToken,
}

#[cfg(target_os = "linux")]
fn checkpoint_control_channel() -> Result<(tokio::net::UnixStream, Stdio)> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    let (parent, child) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| {
        Error::Execution(format!(
            "failed to create checkpoint descriptor channel: {error}"
        ))
    })?;
    let parent = std::os::unix::net::UnixStream::from(parent);
    parent.set_nonblocking(true).map_err(|error| {
        Error::Execution(format!(
            "failed to configure checkpoint descriptor channel: {error}"
        ))
    })?;
    let parent = tokio::net::UnixStream::from_std(parent).map_err(|error| {
        Error::Execution(format!(
            "failed to register checkpoint descriptor channel: {error}"
        ))
    })?;
    Ok((parent, Stdio::from(std::fs::File::from(child))))
}

#[cfg(target_os = "linux")]
async fn send_checkpoint_descriptor(
    control: &tokio::net::UnixStream,
    checkpoint: &std::fs::File,
    marker: u8,
) -> Result<()> {
    loop {
        control.writable().await.map_err(|error| {
            Error::Execution(format!(
                "checkpoint descriptor channel was not writable: {error}"
            ))
        })?;
        match control.try_io(tokio::io::Interest::WRITABLE, || {
            send_checkpoint_descriptor_once(control, checkpoint, marker)
        }) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(Error::Execution(format!(
                    "failed to send checkpoint descriptor: {error}"
                )));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn send_checkpoint_descriptor_once(
    control: &tokio::net::UnixStream,
    checkpoint: &std::fs::File,
    marker: u8,
) -> std::io::Result<()> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    use std::{io::IoSlice, mem::MaybeUninit, os::fd::AsFd as _};

    let descriptors = [checkpoint.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(std::io::Error::other(
            "checkpoint descriptor ancillary buffer is too small",
        ));
    }
    let marker = [marker];
    let sent = sendmsg(
        control,
        &[IoSlice::new(&marker)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )
    .map_err(std::io::Error::from)?;
    if sent != marker.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "checkpoint descriptor marker was not sent",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn supervise_checkpoint_transport(
    mut worker: WorkerProcess,
    mut stdout: tokio::process::ChildStdout,
    handshake_timeout: Duration,
    allowed_supplementary_groups: Vec<u32>,
    mut input: CheckpointTransportInput,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<WasixCheckpointTransportMetadata> {
    let process_id = worker.process_id;
    let outcome = tokio::select! {
        biased;
        _ = &mut cancelled => Err(Error::Cancelled),
        result = tokio::time::timeout(
            handshake_timeout,
            perform_checkpoint_transport(
                &mut worker,
                &mut stdout,
                process_id,
                &allowed_supplementary_groups,
                &mut input,
            ),
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

#[cfg(target_os = "linux")]
async fn perform_checkpoint_transport(
    worker: &mut WorkerProcess,
    stdout: &mut tokio::process::ChildStdout,
    process_id: u32,
    allowed_supplementary_groups: &[u32],
    input: &mut CheckpointTransportInput,
) -> Result<WasixCheckpointTransportMetadata> {
    let ready = read_frame(stdout).await?;
    let metadata: WasixWorkerMetadata = serde_json::from_slice(&ready)
        .map_err(|error| Error::Execution(format!("invalid WASIX worker ready frame: {error}")))?;
    metadata.validate(process_id, allowed_supplementary_groups)?;

    let control = input
        .control
        .as_ref()
        .ok_or_else(|| Error::Execution("checkpoint control socket is unavailable".to_owned()))?;
    let file = input
        .file
        .as_ref()
        .ok_or_else(|| Error::Execution("sealed checkpoint input is unavailable".to_owned()))?;
    send_checkpoint_descriptor(control, file, b'C').await?;
    input.control.take();
    input.file.take();

    let frame = read_frame(stdout).await?;
    let acknowledgement: WasixCheckpointTransportAck =
        serde_json::from_slice(&frame).map_err(|error| {
            Error::Execution(format!("invalid WASIX checkpoint acknowledgement: {error}"))
        })?;
    acknowledgement.validate(input.expected.journal_bytes, &input.expected.journal_sha256)?;
    finish_worker_output(worker, stdout, "checkpoint transport").await?;
    Ok(WasixCheckpointTransportMetadata {
        worker: metadata,
        binding: input.expected.binding.clone(),
        journal_bytes: acknowledgement.journal_bytes,
        journal_sha256: acknowledgement.journal_sha256,
    })
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
async fn supervise_checkpoint_restore(
    mut worker: WorkerProcess,
    mut stdout: tokio::process::ChildStdout,
    handshake_timeout: Duration,
    allowed_supplementary_groups: Vec<u32>,
    mut input: CheckpointRestoreInput,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<WasixCheckpointRestoreMetadata> {
    let process_id = worker.process_id;
    let outcome = tokio::select! {
        biased;
        _ = &mut cancelled => Err(Error::Cancelled),
        result = tokio::time::timeout(
            handshake_timeout,
            perform_checkpoint_restore(
                &mut worker,
                &mut stdout,
                process_id,
                &allowed_supplementary_groups,
                &mut input,
            ),
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

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
async fn perform_checkpoint_restore(
    worker: &mut WorkerProcess,
    stdout: &mut tokio::process::ChildStdout,
    process_id: u32,
    allowed_supplementary_groups: &[u32],
    input: &mut CheckpointRestoreInput,
) -> Result<WasixCheckpointRestoreMetadata> {
    use tokio::io::AsyncWriteExt as _;

    let ready = read_frame(stdout).await?;
    let metadata: WasixWorkerMetadata = serde_json::from_slice(&ready)
        .map_err(|error| Error::Execution(format!("invalid WASIX worker ready frame: {error}")))?;
    metadata.validate(process_id, allowed_supplementary_groups)?;

    let control = input
        .control
        .as_mut()
        .ok_or_else(|| Error::Execution("restore control socket is unavailable".to_owned()))?;
    let module = input
        .module
        .as_ref()
        .ok_or_else(|| Error::Execution("sealed restore module is unavailable".to_owned()))?;
    send_checkpoint_descriptor(control, module, b'M').await?;
    let journal = input
        .journal
        .as_ref()
        .ok_or_else(|| Error::Execution("sealed restore journal is unavailable".to_owned()))?;
    send_checkpoint_descriptor(control, journal, b'C').await?;

    let frame = read_frame(stdout).await?;
    let acknowledgement: WasixCheckpointRestoreAck =
        serde_json::from_slice(&frame).map_err(|error| {
            Error::Execution(format!("invalid WASIX restore acknowledgement: {error}"))
        })?;
    acknowledgement.validate(
        input.expected.module_bytes,
        &input.expected.module_sha256,
        input.expected.journal_bytes,
        &input.expected.journal_sha256,
    )?;

    control
        .write_all(b"E")
        .await
        .map_err(|error| Error::Execution(format!("failed to authorize WASIX restore: {error}")))?;
    control.shutdown().await.map_err(|error| {
        Error::Execution(format!(
            "failed to finish WASIX restore authorization: {error}"
        ))
    })?;
    input.control.take();
    input.module.take();
    input.journal.take();

    let frame = read_frame(stdout).await?;
    let completion: WasixCheckpointRestoreCompletion = serde_json::from_slice(&frame)
        .map_err(|error| Error::Execution(format!("invalid WASIX restore completion: {error}")))?;
    let restored_stdout = read_output_frame(stdout).await?;
    completion.validate(&restored_stdout)?;
    finish_worker_output(worker, stdout, "checkpoint restore").await?;
    Ok(WasixCheckpointRestoreMetadata {
        worker: metadata,
        binding: input.expected.binding.clone(),
        stdout: restored_stdout,
        module_sha256: acknowledgement.module_sha256,
        journal_sha256: acknowledgement.journal_sha256,
    })
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
async fn supervise_checkpoint_capture(
    mut worker: WorkerProcess,
    mut stdout: tokio::process::ChildStdout,
    mut operation: CheckpointCaptureOperation,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<WasixCheckpointCapture> {
    let process_id = worker.process_id;
    let cancellation = operation.cancellation.clone();
    let outcome = tokio::select! {
        biased;
        _ = &mut cancelled => Err(Error::Cancelled),
        () = cancellation.cancelled() => Err(Error::Cancelled),
        result = perform_checkpoint_capture(
            &mut worker,
            &mut stdout,
            process_id,
            &operation.allowed_supplementary_groups,
            operation.handshake_timeout,
            operation.execution_timeout,
            &mut operation.input,
        ) => result,
    };
    if outcome.is_err() && worker.active {
        drop(stdout);
        spawn_worker_reaper(worker);
    }
    outcome
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
async fn perform_checkpoint_capture(
    worker: &mut WorkerProcess,
    stdout: &mut tokio::process::ChildStdout,
    process_id: u32,
    allowed_supplementary_groups: &[u32],
    handshake_timeout: Duration,
    execution_timeout: Duration,
    input: &mut CheckpointCaptureInput,
) -> Result<WasixCheckpointCapture> {
    use tokio::io::AsyncWriteExt as _;

    let (metadata, acknowledgement) = tokio::time::timeout(handshake_timeout, async {
        let ready = read_frame(stdout).await?;
        let metadata: WasixWorkerMetadata = serde_json::from_slice(&ready).map_err(|error| {
            Error::Execution(format!("invalid WASIX capture Ready frame: {error}"))
        })?;
        metadata.validate(process_id, allowed_supplementary_groups)?;
        let control = input
            .control
            .as_mut()
            .ok_or_else(|| Error::Execution("capture control socket is unavailable".to_owned()))?;
        let module = input
            .module
            .as_ref()
            .ok_or_else(|| Error::Execution("sealed capture module is unavailable".to_owned()))?;
        send_checkpoint_descriptor(control, module, b'M').await?;
        write_control_frame(control, &input.request).await?;
        let frame = read_frame(stdout).await?;
        let acknowledgement: WasixCheckpointCaptureAck =
            serde_json::from_slice(&frame).map_err(|error| {
                Error::Execution(format!("invalid WASIX capture acknowledgement: {error}"))
            })?;
        if acknowledgement.module_bytes != input.expected.module_bytes
            || acknowledgement.module_sha256 != input.expected.module_sha256
            || acknowledgement.request_bytes != input.expected.request_bytes
            || acknowledgement.request_sha256 != input.expected.request_sha256
        {
            return Err(Error::Execution(
                "WASIX capture acknowledgement did not match the sealed inputs".to_owned(),
            ));
        }
        control.write_all(b"E").await.map_err(|error| {
            Error::Execution(format!("failed to authorize WASIX capture: {error}"))
        })?;
        control.shutdown().await.map_err(|error| {
            Error::Execution(format!(
                "failed to finish WASIX capture authorization: {error}"
            ))
        })?;
        input.control.take();
        input.module.take();
        Ok((metadata, acknowledgement))
    })
    .await
    .map_err(|_| Error::Timeout)??;

    let (completion, journal, captured_stdout, captured_stderr) =
        tokio::time::timeout(execution_timeout, async {
            let frame = read_frame(stdout).await?;
            let completion: WasixCheckpointCaptureCompletion = serde_json::from_slice(&frame)
                .map_err(|error| {
                    Error::Execution(format!("invalid WASIX capture completion: {error}"))
                })?;
            let journal = read_bounded_worker_frame(
                stdout,
                WASIX_WORKER_MAX_CHECKPOINT_BYTES,
                false,
                "capture journal",
            )
            .await?;
            let captured_stdout = read_bounded_worker_frame(
                stdout,
                WASIX_WORKER_MAX_RESTORE_OUTPUT_BYTES,
                true,
                "capture stdout",
            )
            .await?;
            let captured_stderr = read_bounded_worker_frame(
                stdout,
                WASIX_WORKER_MAX_RESTORE_OUTPUT_BYTES,
                true,
                "capture stderr",
            )
            .await?;
            completion.validate(&journal, &captured_stdout, &captured_stderr)?;
            finish_worker_output(worker, stdout, "checkpoint capture").await?;
            Ok::<_, Error>((completion, journal, captured_stdout, captured_stderr))
        })
        .await
        .map_err(|_| Error::Timeout)??;
    let journal = CapturedWasixJournal::from_attested_worker_capture(
        journal,
        input.expected.binding.clone(),
    )?;
    Ok(WasixCheckpointCapture {
        worker: metadata,
        binding: input.expected.binding.clone(),
        stdout: captured_stdout,
        stderr: captured_stderr,
        module_sha256: acknowledgement.module_sha256,
        journal_sha256: completion.journal_sha256,
        journal,
    })
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
async fn write_control_frame(control: &mut tokio::net::UnixStream, frame: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let length = u32::try_from(frame.len())
        .map_err(|_| Error::Configuration("capture request length overflows u32".to_owned()))?;
    control
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| Error::Execution(format!("failed to send capture request: {error}")))?;
    control
        .write_all(frame)
        .await
        .map_err(|error| Error::Execution(format!("failed to send capture request: {error}")))
}

async fn supervise_probe(
    mut worker: WorkerProcess,
    mut stdout: tokio::process::ChildStdout,
    handshake_timeout: Duration,
    allowed_supplementary_groups: Vec<u32>,
    mut cancelled: oneshot::Receiver<()>,
) -> Result<WasixWorkerMetadata> {
    let process_id = worker.process_id;
    let outcome = tokio::select! {
        biased;
        _ = &mut cancelled => Err(Error::Cancelled),
        result = tokio::time::timeout(
            handshake_timeout,
            perform_handshake(
                &mut worker,
                &mut stdout,
                process_id,
                &allowed_supplementary_groups,
            ),
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
    allowed_supplementary_groups: &[u32],
) -> Result<WasixWorkerMetadata> {
    let frame = read_frame(stdout).await?;
    let metadata: WasixWorkerMetadata = serde_json::from_slice(&frame)
        .map_err(|error| Error::Execution(format!("invalid WASIX worker ready frame: {error}")))?;
    metadata.validate(process_id, allowed_supplementary_groups)?;

    finish_worker_output(worker, stdout, "probe").await?;
    Ok(metadata)
}

async fn finish_worker_output(
    worker: &mut WorkerProcess,
    stdout: &mut tokio::process::ChildStdout,
    operation: &str,
) -> Result<()> {
    let mut trailing = [0_u8; 1];
    if stdout.read(&mut trailing).await.map_err(|error| {
        Error::Execution(format!(
            "failed to finish WASIX worker {operation}: {error}"
        ))
    })? != 0
    {
        return Err(Error::Execution(format!(
            "WASIX worker emitted trailing {operation} bytes"
        )));
    }
    let status = worker.child.wait().await.map_err(|error| {
        Error::Execution(format!(
            "failed to wait for WASIX worker {operation}: {error}"
        ))
    })?;
    worker.kill_tree();
    worker.disarm();
    if !status.success() {
        return Err(Error::Execution(format!(
            "WASIX worker {operation} exited with {status}"
        )));
    }
    Ok(())
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

struct CheckpointTransportSupervisor {
    task: tokio::task::JoinHandle<Result<WasixCheckpointTransportMetadata>>,
    cancel: Option<oneshot::Sender<()>>,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct CheckpointRestoreSupervisor {
    task: tokio::task::JoinHandle<Result<WasixCheckpointRestoreMetadata>>,
    cancel: Option<oneshot::Sender<()>>,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
impl CheckpointRestoreSupervisor {
    const fn new(
        task: tokio::task::JoinHandle<Result<WasixCheckpointRestoreMetadata>>,
        cancel: oneshot::Sender<()>,
    ) -> Self {
        Self {
            task,
            cancel: Some(cancel),
        }
    }

    async fn wait(mut self) -> Result<WasixCheckpointRestoreMetadata> {
        let outcome = (&mut self.task).await.map_err(|error| {
            Error::Execution(format!(
                "WASIX checkpoint restore supervisor failed: {error}"
            ))
        })?;
        self.cancel.take();
        outcome
    }
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
impl Drop for CheckpointRestoreSupervisor {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct CheckpointCaptureSupervisor {
    task: tokio::task::JoinHandle<Result<WasixCheckpointCapture>>,
    cancel: Option<oneshot::Sender<()>>,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
impl CheckpointCaptureSupervisor {
    const fn new(
        task: tokio::task::JoinHandle<Result<WasixCheckpointCapture>>,
        cancel: oneshot::Sender<()>,
    ) -> Self {
        Self {
            task,
            cancel: Some(cancel),
        }
    }

    async fn wait(mut self) -> Result<WasixCheckpointCapture> {
        let outcome = (&mut self.task).await.map_err(|error| {
            Error::Execution(format!(
                "WASIX checkpoint capture supervisor failed: {error}"
            ))
        })?;
        self.cancel.take();
        outcome
    }
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
impl Drop for CheckpointCaptureSupervisor {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

impl CheckpointTransportSupervisor {
    const fn new(
        task: tokio::task::JoinHandle<Result<WasixCheckpointTransportMetadata>>,
        cancel: oneshot::Sender<()>,
    ) -> Self {
        Self {
            task,
            cancel: Some(cancel),
        }
    }

    async fn wait(mut self) -> Result<WasixCheckpointTransportMetadata> {
        let outcome = (&mut self.task).await.map_err(|error| {
            Error::Execution(format!(
                "WASIX checkpoint transport supervisor failed: {error}"
            ))
        })?;
        self.cancel.take();
        outcome
    }
}

impl Drop for CheckpointTransportSupervisor {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

async fn spawn_wasix_worker(
    config: &WasixWorkerConfig,
    operation: WasixWorkerOperation,
    command: &mut Command,
) -> Result<WorkerProcess> {
    configure_worker_parent_death(command);
    #[cfg(unix)]
    command.process_group(0);
    let child = command.spawn().map_err(|error| {
        Error::Execution(format!(
            "failed to spawn WASIX worker {}: {error}",
            config.executable.display()
        ))
    })?;
    let mut worker = WorkerProcess::new(child)?;

    if let Some(placement) = &config.placement {
        let request = WasixWorkerPlacementRequest {
            process_id: worker.process_id,
            operation,
        };
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| placement.place(request)));
        let rejection = match outcome {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(format!(
                "WASIX worker placement rejected the process: {error}"
            )),
            Err(_) => Some("WASIX worker placement policy panicked".to_owned()),
        };
        if let Some(rejection) = rejection {
            worker.kill_tree();
            let _ = worker.child.start_kill();
            let _ = worker.child.wait().await;
            worker.disarm();
            return Err(Error::Execution(rejection));
        }
    }

    Ok(worker)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn configure_worker_parent_death(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    let expected_parent = rustix::process::getpid();
    // SAFETY: this closure runs in the single-threaded post-fork child and uses
    // only async-signal-safe Linux syscalls before exec. Setting PDEATHSIG first
    // and then checking PPID closes the race where the parent dies between fork
    // and prctl: either PPID has changed and exec is rejected, or SIGKILL is
    // already armed for a later parent death.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
                .map_err(std::io::Error::from)?;
            if rustix::process::getppid() != Some(expected_parent) {
                return Err(std::io::Error::from(rustix::io::Errno::SRCH));
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_worker_parent_death(_command: &mut Command) {}

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
    let mut frame = Vec::new();
    frame.try_reserve_exact(length).map_err(|error| {
        Error::Execution(format!("failed to allocate WASIX worker frame: {error}"))
    })?;
    frame.resize(length, 0);
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|error| Error::Execution(format!("failed to read WASIX worker frame: {error}")))?;
    Ok(frame)
}

#[cfg(feature = "wasix-checkpoint")]
async fn read_output_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    read_bounded_worker_frame(
        reader,
        WASIX_WORKER_MAX_RESTORE_OUTPUT_BYTES,
        true,
        "restore output",
    )
    .await
}

#[cfg(feature = "wasix-checkpoint")]
async fn read_bounded_worker_frame(
    reader: &mut (impl AsyncRead + Unpin),
    maximum: usize,
    allow_empty: bool,
    label: &str,
) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await.map_err(|error| {
        Error::Execution(format!("failed to read WASIX {label} length: {error}"))
    })?;
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if (!allow_empty && length == 0) || length > maximum {
        return Err(Error::Execution(format!(
            "WASIX {label} length {length} is invalid"
        )));
    }
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(length)
        .map_err(|error| Error::Execution(format!("failed to allocate WASIX {label}: {error}")))?;
    frame.resize(length, 0);
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|error| Error::Execution(format!("failed to read WASIX {label}: {error}")))?;
    Ok(frame)
}

#[cfg(feature = "wasix")]
fn enter_wasix_worker_isolation() -> std::result::Result<WasixWorkerIsolation, String> {
    #[cfg(target_os = "linux")]
    {
        enter_linux_wasix_worker_isolation()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("the WASIX worker isolation boundary requires Linux".to_owned())
    }
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn rearm_worker_parent_death(
    expected_parent: rustix::process::Pid,
) -> std::result::Result<(), String> {
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|error| format!("failed to re-arm worker parent-death protection: {error}"))?;
    if rustix::process::getppid() != Some(expected_parent) {
        return Err("WASIX worker parent exited during isolation setup".to_owned());
    }
    Ok(())
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn enter_linux_wasix_worker_isolation() -> std::result::Result<WasixWorkerIsolation, String> {
    use nix::unistd::{
        Gid, Uid, getgroups, getresgid, getresuid, setfsgid, setfsuid, setgroups, setresgid,
        setresuid,
    };
    use rustix::{
        process::{DumpableBehavior, Resource},
        thread::{CapabilitySet, CapabilitySets},
    };

    let expected_parent = rustix::process::getppid()
        .ok_or_else(|| "WASIX worker has no live parent process".to_owned())?;
    let closed_inherited_descriptor_count = close_inherited_worker_descriptors()?;
    let core_file_limits = lower_worker_limit(Resource::Core, 0)?;
    let file_size_limits = lower_worker_limit(Resource::Fsize, WASIX_WORKER_MAX_FILE_BYTES)?;
    let address_space_limits =
        lower_worker_limit(Resource::As, WASIX_WORKER_MAX_ADDRESS_SPACE_BYTES)?;
    let open_file_limits = lower_worker_limit(Resource::Nofile, WASIX_WORKER_MAX_OPEN_FILES)?;

    rustix::thread::set_keep_capabilities(false)
        .map_err(|error| format!("failed to disable retained worker capabilities: {error}"))?;
    rustix::thread::clear_ambient_capability_set()
        .map_err(|error| format!("failed to clear ambient worker capabilities: {error}"))?;

    let initial_users = getresuid()
        .map_err(|error| format!("failed to inspect initial worker user IDs: {error}"))?;
    let initial_groups = getresgid()
        .map_err(|error| format!("failed to inspect initial worker group IDs: {error}"))?;
    let has_root_credentials = [
        initial_users.real.as_raw(),
        initial_users.effective.as_raw(),
        initial_users.saved.as_raw(),
        initial_groups.real.as_raw(),
        initial_groups.effective.as_raw(),
        initial_groups.saved.as_raw(),
    ]
    .contains(&0);

    if has_root_credentials {
        let worker_user = Uid::from_raw(65_534);
        let worker_group = Gid::from_raw(65_534);
        setgroups(&[])
            .map_err(|error| format!("failed to clear worker supplementary groups: {error}"))?;
        setresgid(worker_group, worker_group, worker_group)
            .map_err(|error| format!("failed to drop worker group credentials: {error}"))?;
        setresuid(worker_user, worker_user, worker_user)
            .map_err(|error| format!("failed to drop worker user credentials: {error}"))?;
    }

    let final_users =
        getresuid().map_err(|error| format!("failed to inspect final worker user IDs: {error}"))?;
    let final_groups = getresgid()
        .map_err(|error| format!("failed to inspect final worker group IDs: {error}"))?;
    let _previous_filesystem_group = setfsgid(final_groups.effective);
    let _previous_filesystem_user = setfsuid(final_users.effective);

    // Linux clears PDEATHSIG when effective or filesystem credentials change.
    // Re-arm it after every credential transition, then close the corresponding
    // parent-loss race before the worker can report Ready or accept input.
    rearm_worker_parent_death(expected_parent)?;

    let empty_capabilities = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    };
    rustix::thread::set_capabilities(None, empty_capabilities)
        .map_err(|error| format!("failed to clear worker capabilities: {error}"))?;
    rustix::thread::set_no_new_privs(true)
        .map_err(|error| format!("failed to set worker no-new-privileges: {error}"))?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|error| format!("failed to disable worker dumpability: {error}"))?;

    let user_ids = read_linux_status_ids("Uid")?;
    let group_ids = read_linux_status_ids("Gid")?;
    let mut supplementary_groups = getgroups()
        .map_err(|error| format!("failed to verify worker supplementary groups: {error}"))?;
    supplementary_groups.sort_unstable_by_key(|group| group.as_raw());
    let capabilities = rustix::thread::capabilities(None)
        .map_err(|error| format!("failed to verify worker capabilities: {error}"))?;
    let no_new_privileges = rustix::thread::no_new_privs()
        .map_err(|error| format!("failed to verify worker no-new-privileges: {error}"))?;
    let dumpable = rustix::process::dumpable_behavior()
        .map_err(|error| format!("failed to verify worker dumpability: {error}"))?
        != DumpableBehavior::NotDumpable;
    let isolation = WasixWorkerIsolation {
        profile_version: WASIX_WORKER_ISOLATION_PROFILE_VERSION,
        user_ids,
        group_ids,
        supplementary_group_ids: supplementary_groups
            .iter()
            .map(|group| group.as_raw())
            .collect(),
        has_root_supplementary_group: supplementary_groups.iter().any(|group| group.as_raw() == 0),
        no_new_privileges,
        dumpable,
        capability_masks: [
            capabilities.effective.bits(),
            capabilities.permitted.bits(),
            capabilities.inheritable.bits(),
            read_linux_status_mask("CapAmb")?,
        ],
        core_file_limits,
        file_size_limits,
        address_space_limits,
        open_file_limits,
        closed_inherited_descriptor_count,
    };
    isolation
        .validate(isolation.supplementary_group_ids.as_slice())
        .map_err(|error| format!("worker isolation verification failed: {error}"))?;
    Ok(isolation)
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn close_inherited_worker_descriptors() -> std::result::Result<u32, String> {
    let inherited = open_worker_descriptors()?;
    let count = u32::try_from(inherited.len())
        .map_err(|_| "inherited worker descriptor count exceeds the protocol".to_owned())?;
    for descriptor in inherited {
        close_raw_worker_descriptor(descriptor);
    }
    let remaining = open_worker_descriptors()?;
    if !remaining.is_empty() {
        return Err(format!(
            "worker retained inherited descriptors {remaining:?}"
        ));
    }
    Ok(count)
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn open_worker_descriptors() -> std::result::Result<Vec<i32>, String> {
    use nix::{dir::Dir, fcntl::OFlag, sys::stat::Mode};
    use std::os::fd::AsRawFd as _;

    let mut directory = Dir::open(
        "/proc/self/fd",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("failed to inspect inherited worker descriptors: {error}"))?;
    let directory_descriptor = directory.as_raw_fd();
    let mut descriptors = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(|error| {
            format!("failed to enumerate inherited worker descriptors: {error}")
        })?;
        let Some(name) = entry.file_name().to_str().ok() else {
            continue;
        };
        let Ok(descriptor) = name.parse::<i32>() else {
            continue;
        };
        if descriptor > 2 && descriptor != directory_descriptor {
            descriptors.push(descriptor);
        }
    }
    descriptors.sort_unstable();
    descriptors.dedup();
    Ok(descriptors)
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
#[allow(unsafe_code)]
fn close_raw_worker_descriptor(descriptor: i32) {
    // SAFETY: descriptors come from a single-threaded snapshot of
    // /proc/self/fd, excluding this scan's owned directory descriptor. No
    // runtime threads exist yet, so none can close or reuse them concurrently.
    unsafe { rustix::io::close(descriptor) };
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn read_linux_status_mask(field: &str) -> std::result::Result<u64, String> {
    let status = read_linux_status_field(field)?;
    let value = status.trim();
    u64::from_str_radix(value, 16)
        .map_err(|error| format!("worker status contained an invalid {field} mask: {error}"))
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn read_linux_status_ids(field: &str) -> std::result::Result<[u32; 4], String> {
    let status = read_linux_status_field(field)?;
    let values: Vec<_> = status
        .split_whitespace()
        .map(|value| {
            value.parse::<u32>().map_err(|error| {
                format!("worker status contained an invalid {field} identifier: {error}")
            })
        })
        .collect::<std::result::Result<_, _>>()?;
    values
        .try_into()
        .map_err(|_| format!("worker status did not contain four {field} identifiers"))
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn read_linux_status_field(field: &str) -> std::result::Result<String, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("failed to inspect worker security state: {error}"))?;
    status
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == field).then(|| value.trim().to_owned())
        })
        .ok_or_else(|| format!("worker status did not contain {field}"))
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn lower_worker_limit(
    resource: rustix::process::Resource,
    profile_maximum: u64,
) -> std::result::Result<[u64; 2], String> {
    use rustix::process::Rlimit;

    let inherited = rustix::process::getrlimit(resource);
    let maximum = inherited
        .current
        .into_iter()
        .chain(inherited.maximum)
        .fold(profile_maximum, u64::min);
    rustix::process::setrlimit(
        resource,
        Rlimit {
            current: Some(maximum),
            maximum: Some(maximum),
        },
    )
    .map_err(|error| format!("failed to lower worker {resource:?} limit: {error}"))?;
    let installed = rustix::process::getrlimit(resource);
    let current = installed
        .current
        .ok_or_else(|| format!("worker {resource:?} soft limit remained unbounded"))?;
    let hard = installed
        .maximum
        .ok_or_else(|| format!("worker {resource:?} hard limit remained unbounded"))?;
    Ok([current, hard])
}

/// Enter the worker isolation profile and write one version 4 ready frame.
///
/// This function must be called from the worker's initial thread before a
/// Tokio runtime is created and before any guest-controlled bytes are read.
#[doc(hidden)]
#[cfg(feature = "wasix")]
pub fn write_wasix_worker_probe(mut writer: impl Write) -> std::result::Result<(), String> {
    let isolation = enter_wasix_worker_isolation()?;
    let frame = serde_json::to_vec(&WasixWorkerMetadata::current(isolation))
        .map_err(|error| format!("cannot encode worker metadata: {error}"))?;
    write_worker_frame(&mut writer, &frame)
}

/// Enter isolation, receive a sealed descriptor, and acknowledge its exact digest.
///
/// This transport probe never deserializes Wasmer journal records. It must run
/// on the worker's initial thread before any runtime threads are created.
#[doc(hidden)]
#[cfg(all(feature = "wasix", target_os = "linux"))]
pub fn write_wasix_checkpoint_transport_probe(
    reader: impl std::os::fd::AsFd,
    mut writer: impl Write,
) -> std::result::Result<(), String> {
    use rustix::fs::{Mode, OFlags, open};

    let isolation = enter_wasix_worker_isolation()?;
    let ready = serde_json::to_vec(&WasixWorkerMetadata::current(isolation))
        .map_err(|error| format!("cannot encode worker metadata: {error}"))?;
    write_worker_frame(&mut writer, &ready)?;

    let checkpoint = receive_checkpoint_descriptor(&reader, b'C', "checkpoint")?;
    let accepted =
        inspect_sealed_worker_input(&checkpoint, WASIX_WORKER_MAX_CHECKPOINT_BYTES, "checkpoint")?;

    let null = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|error| format!("cannot open null input for checkpoint worker: {error}"))?;
    rustix::stdio::dup2_stdin(&null)
        .map_err(|error| format!("cannot clear checkpoint worker stdin: {error}"))?;
    drop(reader);

    let acknowledgement = WasixCheckpointTransportAck {
        journal_bytes: accepted.bytes,
        journal_sha256: accepted.sha256,
    };
    let frame = serde_json::to_vec(&acknowledgement)
        .map_err(|error| format!("cannot encode checkpoint acknowledgement: {error}"))?;
    write_worker_frame(&mut writer, &frame)
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
struct SealedWorkerInputMetadata {
    bytes: u64,
    sha256: String,
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn inspect_sealed_worker_input(
    descriptor: &impl std::os::fd::AsFd,
    maximum_bytes: usize,
    label: &str,
) -> std::result::Result<SealedWorkerInputMetadata, String> {
    use rustix::fs::{FileType, fcntl_get_seals, fstat};

    let installed = fcntl_get_seals(descriptor)
        .map_err(|error| format!("{label} descriptor does not expose seals: {error}"))?;
    if !installed.contains(REQUIRED_CHECKPOINT_SEALS) {
        return Err(format!("{label} descriptor is not fully sealed"));
    }
    let stat = fstat(descriptor)
        .map_err(|error| format!("cannot inspect sealed {label} descriptor: {error}"))?;
    let bytes =
        u64::try_from(stat.st_size).map_err(|_| format!("{label} descriptor size is negative"))?;
    let maximum_bytes =
        u64::try_from(maximum_bytes).map_err(|_| format!("worker {label} limit overflows u64"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 0
        || bytes == 0
        || bytes > maximum_bytes
    {
        return Err(format!("{label} descriptor identity or size is invalid"));
    }

    let mut hash = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    while offset < bytes {
        let buffer_bytes = u64::try_from(buffer.len())
            .map_err(|_| format!("{label} read buffer length overflows u64"))?;
        let remaining = usize::try_from((bytes - offset).min(buffer_bytes))
            .map_err(|_| format!("{label} read length overflows usize"))?;
        let read = rustix::io::pread(descriptor, &mut buffer[..remaining], offset)
            .map_err(|error| format!("cannot read sealed {label} descriptor: {error}"))?;
        if read == 0 {
            return Err(format!("sealed {label} descriptor ended prematurely"));
        }
        hash.update(&buffer[..read]);
        offset = offset
            .checked_add(
                u64::try_from(read).map_err(|_| format!("{label} read length overflows u64"))?,
            )
            .ok_or_else(|| format!("{label} read offset overflowed"))?;
    }
    let mut trailing = [0_u8; 1];
    if rustix::io::pread(descriptor, &mut trailing, bytes)
        .map_err(|error| format!("cannot finish sealed {label} descriptor: {error}"))?
        != 0
    {
        return Err(format!("sealed {label} descriptor contains trailing bytes"));
    }
    Ok(SealedWorkerInputMetadata {
        bytes,
        sha256: hex::encode(hash.finalize()),
    })
}

/// Restore a checkpoint after validating two sealed inputs and authorization.
#[doc(hidden)]
#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
pub fn write_wasix_checkpoint_restore(
    mut reader: impl std::io::Read + std::os::fd::AsFd,
    mut writer: impl Write,
) -> std::result::Result<(), String> {
    use rustix::fs::{Mode, OFlags, open};

    let isolation = enter_wasix_worker_isolation()?;
    let ready = serde_json::to_vec(&WasixWorkerMetadata::current(isolation))
        .map_err(|error| format!("cannot encode worker metadata: {error}"))?;
    write_worker_frame(&mut writer, &ready)?;

    let module = receive_checkpoint_descriptor(&reader, b'M', "module")?;
    let module_metadata =
        inspect_sealed_worker_input(&module, WASIX_WORKER_MAX_MODULE_BYTES, "module")?;
    let journal = receive_checkpoint_descriptor(&reader, b'C', "checkpoint")?;
    let journal_metadata =
        inspect_sealed_worker_input(&journal, WASIX_WORKER_MAX_CHECKPOINT_BYTES, "checkpoint")?;
    let acknowledgement = WasixCheckpointRestoreAck {
        module_bytes: module_metadata.bytes,
        module_sha256: module_metadata.sha256,
        journal_bytes: journal_metadata.bytes,
        journal_sha256: journal_metadata.sha256,
    };
    let frame = serde_json::to_vec(&acknowledgement)
        .map_err(|error| format!("cannot encode restore acknowledgement: {error}"))?;
    write_worker_frame(&mut writer, &frame)?;

    let mut authorization = [0_u8; 1];
    reader
        .read_exact(&mut authorization)
        .map_err(|error| format!("cannot read restore authorization: {error}"))?;
    if authorization != [b'E'] {
        return Err("restore authorization is malformed".to_owned());
    }
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("cannot finish restore authorization: {error}"))?
        != 0
    {
        return Err("restore authorization contains trailing bytes".to_owned());
    }

    let null = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|error| format!("cannot open null input for restore worker: {error}"))?;
    rustix::stdio::dup2_stdin(&null)
        .map_err(|error| format!("cannot clear restore worker stdin: {error}"))?;
    drop(reader);

    let (exit_code, stdout) =
        execute_wasix_checkpoint_restore(&module, module_metadata.bytes, journal)?;
    let completion = WasixCheckpointRestoreCompletion {
        exit_code,
        stdout_bytes: u64::try_from(stdout.len())
            .map_err(|_| "restore output length overflows u64".to_owned())?,
        stdout_sha256: hex::encode(Sha256::digest(&stdout)),
    };
    let frame = serde_json::to_vec(&completion)
        .map_err(|error| format!("cannot encode restore completion: {error}"))?;
    write_worker_frame(&mut writer, &frame)?;
    write_worker_output_frame(&mut writer, &stdout)
}

/// Capture one explicit WASIX snapshot in an isolated source worker.
#[doc(hidden)]
#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
pub fn write_wasix_checkpoint_capture(
    mut reader: impl std::io::Read + std::os::fd::AsFd,
    mut writer: impl Write,
) -> std::result::Result<(), String> {
    use rustix::fs::{Mode, OFlags, open};

    let isolation = enter_wasix_worker_isolation()?;
    let ready = serde_json::to_vec(&WasixWorkerMetadata::current(isolation))
        .map_err(|error| format!("cannot encode worker metadata: {error}"))?;
    write_worker_frame(&mut writer, &ready)?;

    let module = receive_checkpoint_descriptor(&reader, b'M', "module")?;
    let module_metadata =
        inspect_sealed_worker_input(&module, WASIX_WORKER_MAX_MODULE_BYTES, "module")?;
    let request_bytes = read_worker_control_frame(
        &mut reader,
        WASIX_WORKER_MAX_CAPTURE_REQUEST_BYTES,
        "capture request",
    )?;
    let request: WasixCheckpointCaptureRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| format!("cannot decode capture request: {error}"))?;
    request.validate()?;
    let acknowledgement = WasixCheckpointCaptureAck {
        module_bytes: module_metadata.bytes,
        module_sha256: module_metadata.sha256,
        request_bytes: u64::try_from(request_bytes.len())
            .map_err(|_| "capture request length overflows u64".to_owned())?,
        request_sha256: hex::encode(Sha256::digest(&request_bytes)),
    };
    let frame = serde_json::to_vec(&acknowledgement)
        .map_err(|error| format!("cannot encode capture acknowledgement: {error}"))?;
    write_worker_frame(&mut writer, &frame)?;
    read_worker_execute_authorization(&mut reader, "capture")?;

    let null = open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|error| format!("cannot open null input for capture worker: {error}"))?;
    rustix::stdio::dup2_stdin(&null)
        .map_err(|error| format!("cannot clear capture worker stdin: {error}"))?;
    drop(reader);

    let captured = execute_wasix_checkpoint_capture(&module, module_metadata.bytes, request)?;
    let completion = WasixCheckpointCaptureCompletion {
        exit_code: captured.exit_code,
        journal_bytes: u64::try_from(captured.journal.len())
            .map_err(|_| "capture journal length overflows u64".to_owned())?,
        journal_sha256: hex::encode(Sha256::digest(&captured.journal)),
        stdout_bytes: u64::try_from(captured.stdout.len())
            .map_err(|_| "capture stdout length overflows u64".to_owned())?,
        stdout_sha256: hex::encode(Sha256::digest(&captured.stdout)),
        stderr_bytes: u64::try_from(captured.stderr.len())
            .map_err(|_| "capture stderr length overflows u64".to_owned())?,
        stderr_sha256: hex::encode(Sha256::digest(&captured.stderr)),
    };
    let frame = serde_json::to_vec(&completion)
        .map_err(|error| format!("cannot encode capture completion: {error}"))?;
    write_worker_frame(&mut writer, &frame)?;
    write_worker_bounded_frame(
        &mut writer,
        &captured.journal,
        WASIX_WORKER_MAX_CHECKPOINT_BYTES,
        false,
        "capture journal",
    )?;
    write_worker_output_frame(&mut writer, &captured.stdout)?;
    write_worker_output_frame(&mut writer, &captured.stderr)
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn read_worker_control_frame(
    reader: &mut impl std::io::Read,
    maximum: usize,
    label: &str,
) -> std::result::Result<Vec<u8>, String> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| format!("cannot read {label} length: {error}"))?;
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length == 0 || length > maximum {
        return Err(format!("{label} length {length} is invalid"));
    }
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(length)
        .map_err(|error| format!("cannot allocate {label}: {error}"))?;
    frame.resize(length, 0);
    reader
        .read_exact(&mut frame)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    Ok(frame)
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn read_worker_execute_authorization(
    reader: &mut impl std::io::Read,
    operation: &str,
) -> std::result::Result<(), String> {
    let mut authorization = [0_u8; 1];
    reader
        .read_exact(&mut authorization)
        .map_err(|error| format!("cannot read {operation} authorization: {error}"))?;
    if authorization != [b'E'] {
        return Err(format!("{operation} authorization is malformed"));
    }
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("cannot finish {operation} authorization: {error}"))?
        != 0
    {
        return Err(format!("{operation} authorization contains trailing bytes"));
    }
    Ok(())
}

#[doc(hidden)]
#[cfg(all(feature = "wasix-checkpoint", not(target_os = "linux")))]
pub fn write_wasix_checkpoint_restore(
    _reader: impl Read,
    _writer: impl Write,
) -> std::result::Result<(), String> {
    Err("WASIX checkpoint restore requires Linux".to_owned())
}

#[doc(hidden)]
#[cfg(all(feature = "wasix-checkpoint", not(target_os = "linux")))]
pub fn write_wasix_checkpoint_capture(
    _reader: impl Read,
    _writer: impl Write,
) -> std::result::Result<(), String> {
    Err("WASIX checkpoint capture requires Linux".to_owned())
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn execute_wasix_checkpoint_restore(
    module: &std::os::fd::OwnedFd,
    module_length: u64,
    journal: std::os::fd::OwnedFd,
) -> std::result::Result<(i32, Vec<u8>), String> {
    use crate::wasix_output::BoundedWasixOutput;
    use std::sync::Arc;
    use wasmer::Module;
    use wasmer_wasix::{
        PluggableRuntime, Runtime, UnsupportedVirtualNetworking, WasiEnvBuilder,
        bin_factory::spawn_exec_module,
        runtime::{
            resolver::MultiSource,
            task_manager::{VirtualTaskManagerExt, tokio::TokioTaskManager},
        },
    };

    let module_bytes = read_sealed_module_bytes(module, module_length)?;

    let engine = bounded_wasix_worker_engine();
    let module = Module::new(&engine, &module_bytes)
        .map_err(|error| format!("cannot compile sealed restore module: {error}"))?;
    drop(module_bytes);
    let module_hash = module
        .info()
        .hash()
        .ok_or_else(|| "compiled restore module has no content hash".to_owned())?;

    let journal = checked_restore_journal(journal, module_hash.as_bytes())?;

    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot initialize WASIX restore runtime: {error}"))?;
    let runtime_handle = tokio_runtime.handle().clone();
    let _runtime_guard = runtime_handle.enter();
    let task_manager = Arc::new(TokioTaskManager::new(runtime_handle.clone()));
    let mut concrete_runtime = PluggableRuntime::new(task_manager);
    concrete_runtime.set_engine(engine);
    concrete_runtime.set_networking_implementation(UnsupportedVirtualNetworking::default());
    concrete_runtime.http_client = None;
    concrete_runtime.set_source(MultiSource::default());
    concrete_runtime.add_read_only_journal(journal);
    let runtime: Arc<dyn Runtime + Send + Sync> = Arc::new(concrete_runtime);

    let stdout = BoundedWasixOutput::new(WASIX_WORKER_MAX_RESTORE_OUTPUT_BYTES)
        .map_err(|error| format!("cannot allocate bounded restore output: {error}"))?;
    let mut builder = WasiEnvBuilder::new("restored-checkpoint");
    builder.set_runtime(runtime.clone());
    builder.set_module_hash(module_hash);
    builder.set_stdout(Box::new(stdout.clone()));
    builder.with_skip_stdio_during_bootstrap(true);
    let environment = builder
        .build()
        .map_err(|error| format!("cannot build WASIX restore environment: {error}"))?;
    let mut task = spawn_exec_module(module, environment, &runtime)
        .map_err(|error| format!("cannot spawn restored WASIX process: {error}"))?;
    let exit_code = runtime
        .task_manager()
        .spawn_and_block_on(async move { task.wait_finished().await })
        .map_err(|error| format!("cannot join restored WASIX process: {error}"))?
        .map_err(|error| format!("restored WASIX process failed: {error}"))?;
    if !exit_code.is_success() {
        return Err(format!("restored WASIX process exited with {exit_code}"));
    }
    let output = stdout
        .finish()
        .map_err(|error| format!("cannot finish bounded restore output: {error}"))?;
    Ok((exit_code.raw(), output))
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
struct ExecutedCheckpointCapture {
    exit_code: i32,
    journal: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn execute_wasix_checkpoint_capture(
    module: &std::os::fd::OwnedFd,
    module_length: u64,
    request: WasixCheckpointCaptureRequest,
) -> std::result::Result<ExecutedCheckpointCapture, String> {
    use crate::wasix_output::BoundedWasixOutput;
    use std::sync::Arc;
    use wasmer::Module;
    use wasmer_wasix::{
        PluggableRuntime, Runtime, UnsupportedVirtualNetworking, WasiEnvBuilder,
        bin_factory::spawn_exec_module,
        journal::{LogFileJournal, SnapshotTrigger},
        runtime::{
            resolver::MultiSource,
            task_manager::{VirtualTaskManagerExt, tokio::TokioTaskManager},
        },
    };

    let module_bytes = read_sealed_module_bytes(module, module_length)?;
    let engine = bounded_wasix_worker_engine();
    let module = Module::new(&engine, &module_bytes)
        .map_err(|error| format!("cannot compile sealed capture module: {error}"))?;
    drop(module_bytes);
    let module_hash = module
        .info()
        .hash()
        .ok_or_else(|| "compiled capture module has no content hash".to_owned())?;
    let expected_module_hash = module_hash.as_bytes().to_vec();

    let journal_file = create_capture_journal_file()?;
    let journal = Arc::new(
        LogFileJournal::from_file(
            journal_file
                .try_clone()
                .map_err(|error| format!("cannot clone capture journal memfd: {error}"))?,
        )
        .map_err(|error| format!("cannot open capture journal: {error}"))?,
    );

    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot initialize WASIX capture runtime: {error}"))?;
    let runtime_handle = tokio_runtime.handle().clone();
    let runtime_guard = runtime_handle.enter();
    let task_manager = Arc::new(TokioTaskManager::new(runtime_handle.clone()));
    let mut concrete_runtime = PluggableRuntime::new(task_manager);
    concrete_runtime.set_engine(engine);
    concrete_runtime.set_networking_implementation(UnsupportedVirtualNetworking::default());
    concrete_runtime.http_client = None;
    concrete_runtime.set_source(MultiSource::default());
    concrete_runtime.add_writable_journal(journal.clone());
    let runtime: Arc<dyn Runtime + Send + Sync> = Arc::new(concrete_runtime);

    let stdout = BoundedWasixOutput::new(WASIX_WORKER_MAX_RESTORE_OUTPUT_BYTES)
        .map_err(|error| format!("cannot allocate bounded capture stdout: {error}"))?;
    let stderr = BoundedWasixOutput::new(WASIX_WORKER_MAX_RESTORE_OUTPUT_BYTES)
        .map_err(|error| format!("cannot allocate bounded capture stderr: {error}"))?;
    let mut builder = WasiEnvBuilder::new("checkpoint-source");
    builder.set_runtime(runtime.clone());
    builder.set_module_hash(module_hash);
    builder.add_args(request.arguments);
    builder.add_envs(request.environment);
    builder.set_stdout(Box::new(stdout.clone()));
    builder.set_stderr(Box::new(stderr.clone()));
    builder.with_skip_stdio_during_bootstrap(true);
    builder.add_snapshot_trigger(SnapshotTrigger::Explicit);
    builder.with_stop_running_after_snapshot(true);
    let environment = builder
        .build()
        .map_err(|error| format!("cannot build WASIX capture environment: {error}"))?;
    let mut task = spawn_exec_module(module, environment, &runtime)
        .map_err(|error| format!("cannot spawn WASIX capture process: {error}"))?;
    let exit_code = runtime
        .task_manager()
        .spawn_and_block_on(async move { task.wait_finished().await })
        .map_err(|error| format!("cannot join WASIX capture process: {error}"))?
        .map_err(|error| format!("WASIX capture process failed: {error}"))?;
    if !exit_code.is_success() {
        return Err(format!("WASIX capture process exited with {exit_code}"));
    }
    drop(runtime);
    drop(journal);
    drop(runtime_guard);
    drop(tokio_runtime);
    let captured_stdout = stdout
        .finish()
        .map_err(|error| format!("cannot finish bounded capture stdout: {error}"))?;
    let captured_stderr = stderr
        .finish()
        .map_err(|error| format!("cannot finish bounded capture stderr: {error}"))?;
    let checkpoint_end = inspect_captured_journal(&journal_file, &expected_module_hash)?;
    journal_file
        .set_len(checkpoint_end)
        .map_err(|error| format!("cannot truncate capture journal prefix: {error}"))?;
    rustix::fs::fcntl_add_seals(&journal_file, REQUIRED_CHECKPOINT_SEALS)
        .map_err(|error| format!("cannot seal capture journal: {error}"))?;
    let accepted = inspect_sealed_worker_input(
        &journal_file,
        WASIX_WORKER_MAX_CHECKPOINT_BYTES,
        "capture journal",
    )?;
    let captured_journal = read_sealed_module_bytes(&journal_file, accepted.bytes)?;
    Ok(ExecutedCheckpointCapture {
        exit_code: exit_code.raw(),
        journal: captured_journal,
        stdout: captured_stdout,
        stderr: captured_stderr,
    })
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn create_capture_journal_file() -> std::result::Result<std::fs::File, String> {
    let descriptor = rustix::fs::memfd_create(
        "runtrue-wasix-capture-journal",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )
    .map_err(|error| format!("cannot create capture journal memfd: {error}"))?;
    Ok(std::fs::File::from(descriptor))
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn bounded_wasix_worker_engine() -> wasmer::Engine {
    use wasmer::{
        Pages,
        sys::{BaseTunables, NativeEngineExt as _},
    };

    let mut engine = wasmer::Engine::default();
    let tunables = BaseTunables {
        static_memory_bound: Pages(4_096),
        static_memory_offset_guard_size: 64 * 1024,
        dynamic_memory_offset_guard_size: 64 * 1024,
    };
    engine.set_tunables(tunables);
    engine
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn inspect_captured_journal(
    journal_file: &std::fs::File,
    expected_module_hash: &[u8],
) -> std::result::Result<u64, String> {
    use wasmer_wasix::journal::{JournalEntry, LogFileJournal, ReadableJournal, SnapshotTrigger};

    let inspection = LogFileJournal::from_file(
        journal_file
            .try_clone()
            .map_err(|error| format!("cannot clone completed capture journal: {error}"))?,
    )
    .map_err(|error| format!("cannot inspect completed capture journal: {error}"))?;
    let mut module_records = 0_u32;
    let mut thread_records = 0_u32;
    let mut explicit_snapshots = 0_u32;
    let mut checkpoint_end = None;
    while let Some(record) = inspection
        .read()
        .map_err(|error| format!("cannot decode completed capture journal: {error}"))?
    {
        match record.record {
            JournalEntry::InitModuleV1 { wasm_hash } => {
                if wasm_hash.as_ref() != expected_module_hash {
                    return Err("capture journal module hash does not match the module".to_owned());
                }
                module_records = module_records.saturating_add(1);
            }
            JournalEntry::SetThreadV1 { .. } => {
                thread_records = thread_records.saturating_add(1);
            }
            JournalEntry::SnapshotV1 {
                trigger: SnapshotTrigger::Explicit,
                ..
            } => {
                explicit_snapshots = explicit_snapshots.saturating_add(1);
                checkpoint_end = Some(record.record_end);
            }
            _ => {}
        }
    }
    if module_records != 1 || thread_records == 0 || explicit_snapshots != 1 {
        return Err("capture journal is missing required explicit snapshot state".to_owned());
    }
    checkpoint_end.ok_or_else(|| "capture journal has no explicit snapshot boundary".to_owned())
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn read_sealed_module_bytes(
    module: &impl std::os::fd::AsFd,
    module_length: u64,
) -> std::result::Result<Vec<u8>, String> {
    let module_length = usize::try_from(module_length)
        .map_err(|_| "sealed restore module length overflows usize".to_owned())?;
    let mut module_bytes = Vec::new();
    module_bytes
        .try_reserve_exact(module_length)
        .map_err(|error| format!("cannot allocate sealed restore module: {error}"))?;
    module_bytes.resize(module_length, 0);
    let mut offset = 0_usize;
    while offset < module_bytes.len() {
        let positional_offset = u64::try_from(offset)
            .map_err(|_| "sealed restore module offset overflows u64".to_owned())?;
        let read = rustix::io::pread(module, &mut module_bytes[offset..], positional_offset)
            .map_err(|error| format!("cannot read sealed restore module: {error}"))?;
        if read == 0 {
            return Err("sealed restore module ended before its acknowledged length".to_owned());
        }
        offset = offset
            .checked_add(read)
            .ok_or_else(|| "sealed restore module offset overflowed".to_owned())?;
    }
    Ok(module_bytes)
}

#[cfg(all(feature = "wasix-checkpoint", target_os = "linux"))]
fn checked_restore_journal(
    journal: std::os::fd::OwnedFd,
    module_hash: &[u8],
) -> std::result::Result<std::sync::Arc<wasmer_wasix::journal::LogFileJournal>, String> {
    use wasmer_wasix::journal::{JournalEntry, LogFileJournal, ReadableJournal};

    let journal_file = std::fs::File::from(journal);
    let inspection_file = journal_file
        .try_clone()
        .map_err(|error| format!("cannot clone sealed restore journal: {error}"))?;
    let inspection = LogFileJournal::from_file(inspection_file)
        .map_err(|error| format!("cannot open sealed restore journal: {error}"))?;
    let mut module_records = 0_u32;
    while let Some(record) = inspection
        .read()
        .map_err(|error| format!("cannot inspect sealed restore journal: {error}"))?
    {
        if let JournalEntry::InitModuleV1 { wasm_hash } = record.record {
            if wasm_hash.as_ref() != module_hash {
                return Err(
                    "restore journal module hash does not match the sealed module".to_owned(),
                );
            }
            module_records = module_records
                .checked_add(1)
                .ok_or_else(|| "restore journal module record count overflowed".to_owned())?;
        }
    }
    if module_records != 1 {
        return Err(format!(
            "restore journal contains {module_records} module initialization records"
        ));
    }
    Ok(std::sync::Arc::new(
        LogFileJournal::from_file(journal_file)
            .map_err(|error| format!("cannot reopen sealed restore journal: {error}"))?,
    ))
}

#[cfg(all(feature = "wasix", target_os = "linux"))]
fn receive_checkpoint_descriptor(
    control: &impl std::os::fd::AsFd,
    expected_marker: u8,
    label: &str,
) -> std::result::Result<std::os::fd::OwnedFd, String> {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};
    use std::{io::IoSliceMut, mem::MaybeUninit};

    let mut marker = [0_u8; 1];
    let mut payload = [IoSliceMut::new(&mut marker)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = recvmsg(
        control,
        &mut payload,
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|error| format!("cannot receive {label} descriptor: {error}"))?;
    if message.bytes != 1
        || marker != [expected_marker]
        || message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(format!("{label} descriptor message is malformed"));
    }

    let mut checkpoint = None;
    for message in ancillary.drain() {
        let RecvAncillaryMessage::ScmRights(mut descriptors) = message else {
            return Err(format!(
                "{label} descriptor message has unexpected metadata"
            ));
        };
        let descriptor = descriptors
            .next()
            .ok_or_else(|| format!("{label} descriptor message is empty"))?;
        if checkpoint.replace(descriptor).is_some() || descriptors.next().is_some() {
            return Err(format!(
                "{label} descriptor message contains multiple files"
            ));
        }
    }
    checkpoint.ok_or_else(|| format!("{label} descriptor message did not contain a file"))
}

#[doc(hidden)]
#[cfg(all(feature = "wasix", not(target_os = "linux")))]
pub fn write_wasix_checkpoint_transport_probe(
    _reader: impl Read,
    _writer: impl Write,
) -> std::result::Result<(), String> {
    Err("the WASIX checkpoint transport requires Linux".to_owned())
}

#[cfg(feature = "wasix")]
fn write_worker_frame(writer: &mut impl Write, frame: &[u8]) -> std::result::Result<(), String> {
    if frame.len() > MAX_HANDSHAKE_BYTES {
        return Err("worker metadata exceeds the protocol frame limit".to_owned());
    }
    let length = u32::try_from(frame.len())
        .map_err(|_| "worker metadata exceeds the protocol frame limit".to_owned())?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(frame))
        .and_then(|()| writer.flush())
        .map_err(|error| format!("cannot write worker metadata: {error}"))
}

#[cfg(feature = "wasix-checkpoint")]
fn write_worker_output_frame(
    writer: &mut impl Write,
    frame: &[u8],
) -> std::result::Result<(), String> {
    write_worker_bounded_frame(
        writer,
        frame,
        WASIX_WORKER_MAX_RESTORE_OUTPUT_BYTES,
        true,
        "restore output",
    )
}

#[cfg(feature = "wasix-checkpoint")]
fn write_worker_bounded_frame(
    writer: &mut impl Write,
    frame: &[u8],
    maximum: usize,
    allow_empty: bool,
    label: &str,
) -> std::result::Result<(), String> {
    if (!allow_empty && frame.is_empty()) || frame.len() > maximum {
        return Err(format!("{label} exceeds the protocol frame limit"));
    }
    let length = u32::try_from(frame.len())
        .map_err(|_| format!("{label} exceeds the protocol frame limit"))?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(frame))
        .and_then(|()| writer.flush())
        .map_err(|error| format!("cannot write {label}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[cfg(target_os = "linux")]
    #[test]
    fn cancelled_checkpoint_preparation_stops_before_transport() {
        let cancelled = AtomicBool::new(true);
        assert!(matches!(
            sealed_checkpoint_input(vec![1_u8; 64 * 1024], &cancelled),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn rejects_each_worker_compatibility_mismatch() {
        let process_id = std::process::id();

        let isolation = WasixWorkerIsolation::compatible_for_test();
        let mut metadata = WasixWorkerMetadata::current(isolation.clone());
        metadata.protocol_version += 1;
        assert!(matches!(
            metadata.validate(process_id, &[]),
            Err(Error::UnsupportedComponent(_))
        ));

        let mut metadata = WasixWorkerMetadata::current(isolation.clone());
        metadata.runtime_version.push_str("-other");
        assert!(matches!(
            metadata.validate(process_id, &[]),
            Err(Error::UnsupportedComponent(_))
        ));

        let mut metadata = WasixWorkerMetadata::current(isolation.clone());
        metadata.cohort_id.push_str("-other");
        assert!(matches!(
            metadata.validate(process_id, &[]),
            Err(Error::UnsupportedComponent(_))
        ));

        let mut metadata = WasixWorkerMetadata::current(isolation);
        metadata.process_id = process_id.saturating_add(1);
        assert!(matches!(
            metadata.validate(process_id, &[]),
            Err(Error::Execution(_))
        ));
    }

    #[test]
    fn rejects_each_worker_isolation_mismatch() {
        let compatible = WasixWorkerIsolation::compatible_for_test();
        let mut incompatible = Vec::new();

        let mut isolation = compatible.clone();
        isolation.profile_version += 1;
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.user_ids[1] = 0;
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.group_ids[2] = 0;
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.user_ids[3] = 123;
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.has_root_supplementary_group = true;
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.supplementary_group_ids = vec![123];
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.no_new_privileges = false;
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.dumpable = true;
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.capability_masks[0] = 1;
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.core_file_limits = [1; 2];
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.file_size_limits = [WASIX_WORKER_MAX_FILE_BYTES + 1; 2];
        incompatible.push(isolation);
        let mut isolation = compatible.clone();
        isolation.address_space_limits = [WASIX_WORKER_MAX_ADDRESS_SPACE_BYTES + 1; 2];
        incompatible.push(isolation);
        let mut isolation = compatible;
        isolation.open_file_limits = [65; 2];
        incompatible.push(isolation);

        for isolation in incompatible {
            assert!(isolation.validate(&[]).is_err(), "{isolation:?}");
        }
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
