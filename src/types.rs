use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

/// Standard WASI command generation implemented by a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum WasiVersion {
    /// WASI 0.3 `wasi:cli/command`, using native Component Model async.
    V0_3,
    /// WASI 0.2 `wasi:cli/command` compatibility.
    V0_2,
}

/// Standard WASI world implemented by a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum WasiProfile {
    /// WASI 0.3 command world.
    Cli0_3,
    /// WASI 0.2 command world.
    Cli0_2,
    /// WASI HTTP 0.3 service world.
    Http0_3,
    /// WASI HTTP 0.2 proxy world.
    Http0_2,
}

impl WasiProfile {
    pub(crate) const ALL: [Self; 4] = [Self::Cli0_3, Self::Cli0_2, Self::Http0_3, Self::Http0_2];

    pub(crate) const fn cache_id(self) -> &'static str {
        match self {
            Self::Cli0_3 => "wasi-cli-command-0.3.0",
            Self::Cli0_2 => "wasi-cli-command-0.2",
            Self::Http0_3 => "wasi-http-service-0.3.0",
            Self::Http0_2 => "wasi-http-proxy-0.2",
        }
    }

    /// WASI generation used by this standard world.
    #[must_use]
    pub const fn version(self) -> WasiVersion {
        match self {
            Self::Cli0_3 | Self::Http0_3 => WasiVersion::V0_3,
            Self::Cli0_2 | Self::Http0_2 => WasiVersion::V0_2,
        }
    }

    /// Whether this is a standard WASI command profile.
    #[must_use]
    pub const fn is_command(self) -> bool {
        matches!(self, Self::Cli0_3 | Self::Cli0_2)
    }

    /// Whether this is a standard WASI HTTP handler profile.
    #[must_use]
    pub const fn is_http(self) -> bool {
        matches!(self, Self::Http0_3 | Self::Http0_2)
    }
}

/// Package preparation state observed before an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PackageTier {
    /// Only source component bytes are available.
    Cold,
    /// An authenticated AOT artifact is available on disk.
    DiskAot,
    /// Authenticated immutable AOT bytes are retained in memory.
    Warmish,
    /// A compiled component is retained in memory.
    Warm,
}

/// Lifecycle state of a spawned command invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum InvocationState {
    /// The invocation is eligible to make progress.
    Running,
    /// A pause was requested but has not yet reached a cooperative yield point.
    PauseRequested,
    /// A cooperative pause is retaining the live Store and instance.
    PausedResident,
    /// The paused-residency limit expired and the live invocation was dropped.
    Evicted,
    /// The invocation has returned an output or error.
    Finished,
}

/// Input for a standard WASI command invocation.
#[derive(Debug, Clone)]
pub struct CommandInput {
    /// Bytes exposed through standard input.
    pub stdin: Vec<u8>,
    /// Command-line arguments. No host arguments are inherited.
    pub args: Vec<String>,
    /// Explicit environment variables. No host environment is inherited.
    pub env: BTreeMap<String, String>,
    /// Per-call wall-clock timeout.
    pub timeout: Duration,
    /// Cooperative cancellation observed by the epoch watchdog.
    pub cancellation: CancellationToken,
}

impl Default for CommandInput {
    fn default() -> Self {
        Self {
            stdin: Vec::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(30),
            cancellation: CancellationToken::new(),
        }
    }
}

impl CommandInput {
    /// Construct an invocation with the supplied standard-input bytes.
    #[must_use]
    pub fn new(stdin: impl Into<Vec<u8>>) -> Self {
        Self {
            stdin: stdin.into(),
            ..Self::default()
        }
    }

    /// Set the command arguments.
    #[must_use]
    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Set one explicit environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set the per-call wall-clock timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Output from a standard WASI command invocation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CommandOutput {
    /// Captured standard output bytes.
    pub stdout: Vec<u8>,
    /// Captured standard error bytes.
    pub stderr: Vec<u8>,
    /// Portable process-style exit code (`0` for success, `1` for `result::err`).
    pub exit_code: u8,
    /// WASI command generation selected for the component.
    pub wasi_version: WasiVersion,
    /// Timing and tier information for this call.
    pub measurement: crate::RunMeasurement,
}

/// Cloneable cancellation signal for one or more calls.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<CancellationState>);

#[derive(Debug, Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    /// Create an uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.notify.notify_waiters();
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.0.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Cooperative pause signal for a live command invocation.
///
/// A pause retains the Store and guest state. It is observed at Wasmtime async
/// and epoch yield points, so it is not an instruction-level stop signal.
#[derive(Debug, Clone, Default)]
pub struct PauseToken(Arc<PauseState>);

#[derive(Debug, Default)]
struct PauseState {
    paused: AtomicBool,
    resident: AtomicBool,
    evicted: AtomicBool,
    timing: Mutex<PauseTiming>,
    notify: Notify,
}

#[derive(Debug, Default)]
struct PauseTiming {
    completed: Duration,
    paused_at: Option<Instant>,
}

impl PauseToken {
    /// Create an unpaused signal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a cooperative pause.
    pub(crate) fn pause(&self) {
        let mut timing = self.timing();
        if !self.0.paused.swap(true, Ordering::AcqRel) {
            self.0.resident.store(false, Ordering::Release);
            timing.paused_at = Some(Instant::now());
        }
    }

    /// Resume a resident invocation.
    pub(crate) fn resume(&self) -> bool {
        if self.is_evicted() {
            return false;
        }
        let mut timing = self.timing();
        if self.0.paused.swap(false, Ordering::AcqRel) {
            self.0.resident.store(false, Ordering::Release);
            if let Some(started) = timing.paused_at.take() {
                timing.completed = timing.completed.saturating_add(started.elapsed());
            }
            self.0.notify.notify_waiters();
        }
        true
    }

    /// Whether a pause has been requested and not resumed.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.0.paused.load(Ordering::Acquire)
    }

    pub(crate) fn is_evicted(&self) -> bool {
        self.0.evicted.load(Ordering::Acquire)
    }

    pub(crate) fn is_resident(&self) -> bool {
        self.0.resident.load(Ordering::Acquire)
    }

    pub(crate) fn mark_resident(&self) {
        if self.is_paused() && !self.is_evicted() {
            self.0.resident.store(true, Ordering::Release);
            self.0.notify.notify_waiters();
        }
    }

    pub(crate) fn total_paused(&self) -> Duration {
        let timing = self.timing();
        timing.completed.saturating_add(
            timing
                .paused_at
                .map_or(Duration::ZERO, |started| started.elapsed()),
        )
    }

    pub(crate) async fn wait(&self, cancellation: &CancellationToken, resident_ttl: Duration) {
        loop {
            let notified = self.0.notify.notified();
            if !self.is_paused() || cancellation.is_cancelled() {
                return;
            }
            let remaining = {
                let timing = self.timing();
                timing.paused_at.map_or(resident_ttl, |started| {
                    resident_ttl.saturating_sub(started.elapsed())
                })
            };
            if remaining.is_zero() {
                self.evict(cancellation);
                return;
            }
            tokio::select! {
                () = notified => {}
                () = cancellation.cancelled() => return,
                () = tokio::time::sleep(remaining) => {
                    if self.is_paused() {
                        self.evict(cancellation);
                    }
                    return;
                }
            }
        }
    }

    fn evict(&self, cancellation: &CancellationToken) {
        self.0.evicted.store(true, Ordering::Release);
        self.0.resident.store(false, Ordering::Release);
        cancellation.cancel();
        self.0.notify.notify_waiters();
    }

    fn timing(&self) -> std::sync::MutexGuard<'_, PauseTiming> {
        self.0
            .timing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
