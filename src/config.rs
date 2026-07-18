use crate::DiskCacheConfig;
use std::time::Duration;

/// Per-invocation resource limits.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeLimits {
    /// Maximum input bytes.
    pub max_input_bytes: usize,
    /// Maximum bytes captured independently for stdout and stderr.
    pub max_output_bytes: usize,
    /// Maximum linear-memory size per memory.
    pub max_memory_bytes: usize,
    /// Maximum table elements per table.
    pub max_table_elements: usize,
    /// Maximum component instances in a Store.
    pub max_instances: usize,
    /// Fuel supplied to each invocation.
    pub fuel: u64,
    /// Maximum caller-selected timeout.
    pub max_timeout: Duration,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_output_bytes: 16 * 1024 * 1024,
            max_memory_bytes: 256 * 1024 * 1024,
            max_table_elements: 100_000,
            max_instances: 100,
            fuel: 10_000_000_000,
            max_timeout: Duration::from_secs(300),
        }
    }
}

/// Runtime, cache, and background-promotion configuration.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Maximum compiled Components retained in memory.
    pub max_warm_components: usize,
    /// Maximum AOT artifacts retained in memory.
    pub max_warmish_entries: usize,
    /// Maximum combined in-memory AOT bytes.
    pub max_warmish_bytes: usize,
    /// Maximum concurrent background promotions.
    pub background_workers: usize,
    /// Maximum time a cooperatively paused Store and instance remain resident.
    pub paused_resident_ttl: Duration,
    /// Epoch watchdog interval.
    pub epoch_interval: Duration,
    /// Optional authenticated on-disk AOT cache.
    pub disk_cache: Option<DiskCacheConfig>,
    /// Per-call limits.
    pub limits: RuntimeLimits,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_warm_components: 64,
            max_warmish_entries: 1_024,
            max_warmish_bytes: 512 * 1024 * 1024,
            background_workers: 2,
            paused_resident_ttl: Duration::from_secs(30),
            epoch_interval: Duration::from_millis(10),
            disk_cache: None,
            limits: RuntimeLimits::default(),
        }
    }
}
