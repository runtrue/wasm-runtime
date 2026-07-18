use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Standard WASI command generation implemented by a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WasiVersion {
    /// WASI 0.3 `wasi:cli/command`, using native Component Model async.
    V0_3,
    /// WASI 0.2 `wasi:cli/command` compatibility.
    V0_2,
}

impl WasiVersion {
    pub(crate) const fn cache_id(self) -> &'static str {
        match self {
            Self::V0_3 => "wasi-cli-command-0.3.0",
            Self::V0_2 => "wasi-cli-command-0.2",
        }
    }
}

/// Package preparation state observed before an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Create an uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
