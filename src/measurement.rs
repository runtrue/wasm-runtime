use crate::{PackageTier, WasiVersion};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Timings for the major phases of an invocation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhaseTimings {
    /// Time spent locating, authenticating, compiling, or deserializing code.
    pub prepare: Duration,
    /// Time spent creating the fresh Store and instantiating the component.
    pub instantiate: Duration,
    /// Time spent inside the guest command.
    pub execute: Duration,
    /// Complete call duration.
    pub total: Duration,
}

/// Tier and timing evidence for one invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeasurement {
    /// Tier observed before preparation started.
    pub prepared_from: PackageTier,
    /// Tier retained after preparation completed.
    pub retained_as: PackageTier,
    /// Selected standard WASI command generation.
    pub wasi_version: WasiVersion,
    /// Major phase timings.
    pub phases: PhaseTimings,
}
