//! A standards-first WebAssembly Component runtime.
//!
//! The runtime executes standard `wasi:cli/command` components, targets WASI
//! 0.3 first, retains WASI 0.2 compatibility, and promotes packages through
//! cold, authenticated disk AOT, in-memory AOT (warmish), and compiled
//! component (warm) tiers. Every call receives a fresh Store and WASI context.

mod cache;
mod checkpoint;
mod config;
mod environment;
mod error;
mod http;
mod measurement;
mod runtime;
mod types;
#[cfg(feature = "wasix-checkpoint")]
mod wasix_output;
mod wasix_worker;

pub use cache::{AotAuthenticationKey, DiskCacheConfig};
pub use checkpoint::{
    CapturedWasixJournal, CheckpointAuthenticationKey, VerifiedWasixCheckpoint,
    WasixCheckpointBinding, WasixCheckpointCodec,
};
pub use config::{RuntimeConfig, RuntimeLimits};
pub use environment::{
    EnvironmentArtifact, EnvironmentBuild, EnvironmentCommands, EnvironmentFilesystem,
    EnvironmentLanguage, EnvironmentManifest,
};
pub use error::{
    Error, Result, WasixCheckpointCaptureFailure, WasixCheckpointCaptureFailureReason,
    WasixCheckpointCapturePhase, WasixCheckpointRestoreFailure,
    WasixCheckpointRestoreFailureReason, WasixCheckpointRestorePhase, WasixWorkerDiagnostics,
};
pub use http::{
    HttpDispatchMetadata, HttpRequest, HttpResponse, HttpService, HttpServiceConfig,
    HttpServiceMetrics, HttpServiceState, OutboundHttpGrant, StreamingHttpBody,
};
pub use measurement::{PhaseTimings, RunMeasurement};
pub use runtime::{Program, RunningCommand, Runtime, RuntimeBuilder, RuntimeMetrics};
pub use types::{
    CancellationToken, CommandInput, CommandOutput, InvocationState, PackageTier, PauseToken,
    WasiProfile, WasiVersion,
};
#[cfg(feature = "wasix-checkpoint")]
#[doc(hidden)]
pub use wasix_worker::write_wasix_checkpoint_capture;
#[cfg(feature = "wasix-checkpoint")]
#[doc(hidden)]
pub use wasix_worker::write_wasix_checkpoint_restore;
pub use wasix_worker::{
    WASIX_COHORT_ID, WASIX_WORKER_PROTOCOL_VERSION, WasixCheckpointTransportMetadata,
    WasixWorkerConfig, WasixWorkerIsolation, WasixWorkerMetadata, WasixWorkerOperation,
    WasixWorkerPlacement, WasixWorkerPlacementRequest, probe_wasix_checkpoint_transport,
    probe_wasix_worker,
};
#[cfg(feature = "wasix-checkpoint")]
pub use wasix_worker::{WasixCheckpointCapture, capture_wasix_checkpoint};
#[cfg(feature = "wasix-checkpoint")]
pub use wasix_worker::{WasixCheckpointRestoreMetadata, restore_wasix_checkpoint};
#[cfg(feature = "wasix")]
#[doc(hidden)]
pub use wasix_worker::{write_wasix_checkpoint_transport_probe, write_wasix_worker_probe};

/// Exact Wasmtime release used to compile serialized artifacts.
pub const WASMTIME_VERSION: &str = "46.0.1";

/// Primary WASI version supported by this release.
pub const PRIMARY_WASI_VERSION: &str = "0.3.0";
