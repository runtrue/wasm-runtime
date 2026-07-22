use crate::{Error, Result};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasix")]
use std::io::Write;
use std::{
    fs,
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
pub const WASIX_WORKER_PROTOCOL_VERSION: u32 = 2;

/// Exact engine and package cohort required for worker compatibility.
pub const WASIX_COHORT_ID: &str = "wasmer-7.1.0+wasix-0.701.0+webc-11.0.0";

const WASIX_WORKER_ISOLATION_PROFILE_VERSION: u32 = 1;
const WASIX_WORKER_MAX_OPEN_FILES: u64 = 64;
const WASIX_WORKER_MAX_SUPPLEMENTARY_GROUPS: usize = 64;
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Explicit deployment configuration for the out-of-process WASIX worker.
///
/// The executable is a deployment trust anchor and must be installed at a
/// trusted, administrator-controlled path. The protocol probe checks reported
/// compatibility; it is not a signature over the executable. Version 2 of the
/// worker process boundary is supported on Linux only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasixWorkerConfig {
    executable: PathBuf,
    handshake_timeout: Duration,
    allowed_supplementary_groups: Vec<u32>,
}

impl WasixWorkerConfig {
    /// Select an absolute worker executable path with a five-second handshake.
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            handshake_timeout: Duration::from_secs(5),
            allowed_supplementary_groups: Vec::new(),
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
        config.allowed_supplementary_groups.clone(),
        cancelled,
    ));
    ProbeSupervisor::new(supervisor, cancel).wait().await
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
fn enter_linux_wasix_worker_isolation() -> std::result::Result<WasixWorkerIsolation, String> {
    use nix::unistd::{
        Gid, Uid, getgroups, getresgid, getresuid, setfsgid, setfsuid, setgroups, setresgid,
        setresuid,
    };
    use rustix::{
        process::{DumpableBehavior, Resource},
        thread::{CapabilitySet, CapabilitySets},
    };

    let closed_inherited_descriptor_count = close_inherited_worker_descriptors()?;
    let core_file_limits = lower_worker_limit(Resource::Core, 0)?;
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

/// Enter the worker isolation profile and write one version 2 ready frame.
///
/// This function must be called from the worker's initial thread before a
/// Tokio runtime is created and before any guest-controlled bytes are read.
#[doc(hidden)]
#[cfg(feature = "wasix")]
pub fn write_wasix_worker_probe(mut writer: impl Write) -> std::result::Result<(), String> {
    let isolation = enter_wasix_worker_isolation()?;
    let frame = serde_json::to_vec(&WasixWorkerMetadata::current(isolation))
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
