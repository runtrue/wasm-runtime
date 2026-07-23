use std::io;

/// Restore protocol phase in which a checkpoint operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WasixCheckpointRestorePhase {
    /// The destination worker did not complete its compatibility handshake.
    #[error("worker readiness")]
    Ready,
    /// Sealed module or checkpoint inputs were not accepted.
    #[error("sealed input transfer")]
    Input,
    /// The worker could not be authorized to execute the restore.
    #[error("execution authorization")]
    Authorization,
    /// The authenticated checkpoint could not be replayed.
    #[error("checkpoint execution")]
    Execution,
    /// Bounded guest output was malformed or incomplete.
    #[error("output collection")]
    Output,
    /// The worker did not shut down cleanly after quiescing.
    #[error("worker shutdown")]
    Shutdown,
}

/// Capture protocol phase in which a checkpoint operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WasixCheckpointCapturePhase {
    /// The source worker did not complete its compatibility handshake.
    #[error("worker readiness")]
    Ready,
    /// Sealed module or capture request inputs were not accepted.
    #[error("sealed input transfer")]
    Input,
    /// The worker could not be authorized to execute the capture.
    #[error("execution authorization")]
    Authorization,
    /// The source workload did not reach a valid explicit checkpoint.
    #[error("checkpoint execution")]
    Execution,
    /// Bounded checkpoint or guest output was malformed or incomplete.
    #[error("output collection")]
    Output,
    /// The worker did not shut down cleanly after capture.
    #[error("worker shutdown")]
    Shutdown,
}

/// Stable, non-secret classification of a checkpoint restore failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WasixCheckpointRestoreFailureReason {
    /// The worker violated or could not complete the authenticated protocol.
    #[error("worker protocol failure")]
    Protocol,
    /// The guest checkpoint or WASIX runtime failed during replay.
    #[error("checkpoint runtime failure")]
    Runtime,
    /// A bounded resource or output limit was exceeded.
    #[error("checkpoint resource limit")]
    ResourceLimit,
    /// The worker process failed to exit successfully.
    #[error("worker process failure")]
    WorkerProcess,
}

/// Stable, non-secret classification of a checkpoint capture failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WasixCheckpointCaptureFailureReason {
    /// The worker violated or could not complete the authenticated protocol.
    #[error("worker protocol failure")]
    Protocol,
    /// The source workload or WASIX runtime failed during capture.
    #[error("checkpoint runtime failure")]
    Runtime,
    /// A bounded resource, checkpoint, or output limit was exceeded.
    #[error("checkpoint resource limit")]
    ResourceLimit,
    /// The worker process failed to exit successfully.
    #[error("worker process failure")]
    WorkerProcess,
}

/// Bounded diagnostics emitted by an isolated worker process.
///
/// These bytes are separate from guest standard error. Debug formatting is
/// deliberately redacted so error logs do not disclose module, argument, or
/// environment details unless a caller explicitly retrieves the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct WasixWorkerDiagnostics {
    bytes: Vec<u8>,
    truncated: bool,
}

impl std::fmt::Debug for WasixWorkerDiagnostics {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasixWorkerDiagnostics")
            .field("bytes", &self.bytes.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl WasixWorkerDiagnostics {
    #[cfg(feature = "wasix-checkpoint")]
    pub(crate) const fn new(bytes: Vec<u8>, truncated: bool) -> Self {
        Self { bytes, truncated }
    }

    /// Explicitly access bounded worker-process diagnostics.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether diagnostics exceeded the capture limit and were truncated.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Number of retained diagnostic bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether no worker-process diagnostics were emitted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Structured checkpoint restore failure with explicitly accessed diagnostics.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[error("WASIX checkpoint restore failed during {phase}: {reason}")]
pub struct WasixCheckpointRestoreFailure {
    phase: WasixCheckpointRestorePhase,
    reason: WasixCheckpointRestoreFailureReason,
    diagnostics: WasixWorkerDiagnostics,
    exit_code: Option<i32>,
    exit_signal: Option<i32>,
}

/// Structured checkpoint capture failure with explicitly accessed diagnostics.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[error("WASIX checkpoint capture failed during {phase}: {reason}")]
pub struct WasixCheckpointCaptureFailure {
    phase: WasixCheckpointCapturePhase,
    reason: WasixCheckpointCaptureFailureReason,
    diagnostics: WasixWorkerDiagnostics,
    exit_code: Option<i32>,
    exit_signal: Option<i32>,
}

impl std::fmt::Debug for WasixCheckpointRestoreFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasixCheckpointRestoreFailure")
            .field("phase", &self.phase)
            .field("reason", &self.reason)
            .field("diagnostics", &self.diagnostics)
            .field("exit_code", &self.exit_code)
            .field("exit_signal", &self.exit_signal)
            .finish()
    }
}

impl std::fmt::Debug for WasixCheckpointCaptureFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WasixCheckpointCaptureFailure")
            .field("phase", &self.phase)
            .field("reason", &self.reason)
            .field("diagnostics", &self.diagnostics)
            .field("exit_code", &self.exit_code)
            .field("exit_signal", &self.exit_signal)
            .finish()
    }
}

impl WasixCheckpointRestoreFailure {
    #[cfg(feature = "wasix-checkpoint")]
    pub(crate) const fn new(
        phase: WasixCheckpointRestorePhase,
        reason: WasixCheckpointRestoreFailureReason,
        diagnostics: WasixWorkerDiagnostics,
    ) -> Self {
        Self {
            phase,
            reason,
            diagnostics,
            exit_code: None,
            exit_signal: None,
        }
    }

    #[cfg(feature = "wasix-checkpoint")]
    pub(crate) const fn with_exit_status(
        mut self,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
    ) -> Self {
        self.exit_code = exit_code;
        self.exit_signal = exit_signal;
        self
    }

    /// Restore protocol phase that failed.
    #[must_use]
    pub const fn phase(&self) -> WasixCheckpointRestorePhase {
        self.phase
    }

    /// Stable failure category suitable for metrics and retry policy.
    #[must_use]
    pub const fn reason(&self) -> WasixCheckpointRestoreFailureReason {
        self.reason
    }

    /// Bounded, explicitly accessed worker-process diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> &WasixWorkerDiagnostics {
        &self.diagnostics
    }

    /// Portable worker exit code, when the failed worker exited normally.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Unix signal that terminated the failed worker, when observable.
    #[must_use]
    pub const fn exit_signal(&self) -> Option<i32> {
        self.exit_signal
    }
}

impl WasixCheckpointCaptureFailure {
    #[cfg(feature = "wasix-checkpoint")]
    pub(crate) const fn new(
        phase: WasixCheckpointCapturePhase,
        reason: WasixCheckpointCaptureFailureReason,
        diagnostics: WasixWorkerDiagnostics,
    ) -> Self {
        Self {
            phase,
            reason,
            diagnostics,
            exit_code: None,
            exit_signal: None,
        }
    }

    #[cfg(feature = "wasix-checkpoint")]
    pub(crate) const fn with_exit_status(
        mut self,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
    ) -> Self {
        self.exit_code = exit_code;
        self.exit_signal = exit_signal;
        self
    }

    /// Capture protocol phase that failed.
    #[must_use]
    pub const fn phase(&self) -> WasixCheckpointCapturePhase {
        self.phase
    }

    /// Stable failure category suitable for metrics and retry policy.
    #[must_use]
    pub const fn reason(&self) -> WasixCheckpointCaptureFailureReason {
        self.reason
    }

    /// Bounded, explicitly accessed worker-process diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> &WasixWorkerDiagnostics {
        &self.diagnostics
    }

    /// Portable worker exit code, when the failed worker exited normally.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Unix signal that terminated the failed worker, when observable.
    #[must_use]
    pub const fn exit_signal(&self) -> Option<i32> {
        self.exit_signal
    }
}

/// Runtime result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the runtime.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Runtime configuration was invalid.
    #[error("invalid runtime configuration: {0}")]
    Configuration(String),
    /// The component could not be read.
    #[error("component I/O failed: {0}")]
    Io(String),
    /// The component failed compilation or deserialization.
    #[error("component preparation failed: {0}")]
    Preparation(String),
    /// The component does not implement a supported standard command world.
    #[error("unsupported component: {0}")]
    UnsupportedComponent(String),
    /// Component instantiation or execution failed.
    #[error("component execution failed: {0}")]
    Execution(String),
    /// A configured resource limit was exceeded.
    #[error("runtime limit exceeded: {0}")]
    Limit(&'static str),
    /// Execution was cancelled.
    #[error("component execution was cancelled")]
    Cancelled,
    /// A paused invocation exceeded its configured resident lifetime.
    #[error("paused invocation was evicted after its resident lifetime expired")]
    IdleEvicted,
    /// An operation was not valid for the invocation's current lifecycle state.
    #[error("invalid invocation state: {0}")]
    InvalidState(&'static str),
    /// Execution exceeded its wall-clock deadline.
    #[error("component execution timed out")]
    Timeout,
    /// Authenticated cache state was invalid and could not be recovered.
    #[error("AOT cache failed: {0}")]
    Cache(String),
    /// A WASIX checkpoint artifact was invalid or incompatible.
    #[error("WASIX checkpoint failed: {0}")]
    Checkpoint(String),
    /// An isolated WASIX destination failed during a specific restore phase.
    #[error(transparent)]
    CheckpointRestore(WasixCheckpointRestoreFailure),
    /// An isolated WASIX source failed during a specific capture phase.
    #[error(transparent)]
    CheckpointCapture(WasixCheckpointCaptureFailure),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
