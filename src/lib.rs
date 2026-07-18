//! A standards-first WebAssembly Component runtime.
//!
//! The runtime executes standard `wasi:cli/command` components, targets WASI
//! 0.3 first, retains WASI 0.2 compatibility, and promotes packages through
//! cold, authenticated disk AOT, in-memory AOT (warmish), and compiled
//! component (warm) tiers. Every call receives a fresh Store and WASI context.

mod cache;
mod config;
mod error;
mod measurement;
mod runtime;
mod types;

pub use cache::{AotAuthenticationKey, DiskCacheConfig};
pub use config::{RuntimeConfig, RuntimeLimits};
pub use error::{Error, Result};
pub use measurement::{PhaseTimings, RunMeasurement};
pub use runtime::{Program, Runtime, RuntimeBuilder};
pub use types::{CancellationToken, CommandInput, CommandOutput, PackageTier, WasiVersion};

/// Exact Wasmtime release used to compile serialized artifacts.
pub const WASMTIME_VERSION: &str = "46.0.1";

/// Primary WASI version supported by this release.
pub const PRIMARY_WASI_VERSION: &str = "0.3.0";
