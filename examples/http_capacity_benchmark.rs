//! AOT storage and resident HTTP worker capacity benchmark.

use runtrue_wasm_runtime::{
    AotAuthenticationKey, DiskCacheConfig, HttpRequest, HttpService, HttpServiceConfig, Runtime,
    RuntimeConfig,
};
use serde::Serialize;
use std::{fs, path::Path, time::Duration};

const COMPONENT: &[u8] = include_bytes!("../tests/fixtures/p3-http-hello.component.wasm");
const COUNTS: [usize; 4] = [1, 100, 1_000, 10_000];

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    host_os: &'static str,
    host_arch: &'static str,
    wasmtime_version: &'static str,
    wasi_profile: &'static str,
    source_component_bytes: usize,
    authenticated_aot_bytes: u64,
    package_storage: Vec<PackageStorage>,
    resident_workers: Vec<ResidentWorkers>,
    worker_projection_basis: WorkerBasis,
}

#[derive(Serialize)]
struct PackageStorage {
    packages: usize,
    identical_digest_aot_bytes: u64,
    unique_digest_aot_projection_bytes: u64,
    source_projection_bytes: u64,
}

#[derive(Serialize)]
struct ResidentWorkers {
    workers: usize,
    measured: bool,
    rss_bytes: Option<u64>,
    rss_delta_bytes: Option<u64>,
}

#[derive(Serialize)]
struct WorkerBasis {
    measured_workers: usize,
    runtime_baseline_rss_bytes: u64,
    one_worker_rss_bytes: u64,
    measured_rss_bytes: u64,
    marginal_rss_per_worker_bytes: u64,
    projected_workers_per_gib: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let max_measured_workers = std::env::args()
        .nth(1)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(100);
    if max_measured_workers == 0 || std::env::args().nth(2).is_some() {
        return Err("usage: http_capacity_benchmark [positive-max-measured-workers]".into());
    }

    let directory = tempfile::TempDir::new()?;
    let config = RuntimeConfig {
        disk_cache: Some(DiskCacheConfig::new(
            directory.path(),
            AotAuthenticationKey::new([63; 32]),
        )),
        max_warm_components: 1,
        max_warmish_entries: 1,
        ..RuntimeConfig::default()
    };
    let runtime = Runtime::new(config)?;
    let program = runtime.load_bytes(COMPONENT)?;
    let baseline_rss = rss_bytes()?;
    let mut services: Vec<HttpService> = Vec::new();
    let mut measured = Vec::new();
    for workers in 1..=max_measured_workers {
        let service = program
            .http_service(HttpServiceConfig {
                idle_worker_ttl: Duration::from_secs(300),
                ..HttpServiceConfig::default()
            })
            .await?;
        service
            .handle(HttpRequest::new(
                "GET",
                "http://capacity.local/",
                Vec::new(),
            ))
            .await?;
        services.push(service);
        if COUNTS.contains(&workers) || workers == max_measured_workers {
            measured.push((workers, rss_bytes()?));
        }
    }
    let measured_rss = rss_bytes()?;
    let one_worker_rss = measured
        .iter()
        .find(|(workers, _)| *workers == 1)
        .map_or(measured_rss, |(_, rss)| *rss);
    let marginal = measured_rss
        .saturating_sub(one_worker_rss)
        .checked_div(max_measured_workers.saturating_sub(1) as u64)
        .unwrap_or(0);
    let aot_bytes = extension_bytes(directory.path(), "aot")?;
    let residents = COUNTS
        .into_iter()
        .map(|workers| {
            let value = measured
                .iter()
                .find(|(count, _)| *count == workers)
                .map(|(_, rss)| *rss);
            ResidentWorkers {
                workers,
                measured: value.is_some(),
                rss_bytes: value,
                rss_delta_bytes: value.map(|rss| rss.saturating_sub(baseline_rss)),
            }
        })
        .collect();
    let report = Report {
        schema: "standalone-wasm-http-capacity-v1",
        host_os: std::env::consts::OS,
        host_arch: std::env::consts::ARCH,
        wasmtime_version: runtrue_wasm_runtime::WASMTIME_VERSION,
        wasi_profile: "wasi:http/service@0.3.0",
        source_component_bytes: COMPONENT.len(),
        authenticated_aot_bytes: aot_bytes,
        package_storage: package_storage(aot_bytes),
        resident_workers: residents,
        worker_projection_basis: WorkerBasis {
            measured_workers: max_measured_workers,
            runtime_baseline_rss_bytes: baseline_rss,
            one_worker_rss_bytes: one_worker_rss,
            measured_rss_bytes: measured_rss,
            marginal_rss_per_worker_bytes: marginal,
            projected_workers_per_gib: if marginal == 0 {
                0
            } else {
                (1_u64 << 30) / marginal
            },
        },
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    drop(services);
    Ok(())
}

fn package_storage(aot_bytes: u64) -> Vec<PackageStorage> {
    COUNTS
        .into_iter()
        .map(|packages| PackageStorage {
            packages,
            identical_digest_aot_bytes: aot_bytes,
            unique_digest_aot_projection_bytes: aot_bytes.saturating_mul(packages as u64),
            source_projection_bytes: (COMPONENT.len() as u64).saturating_mul(packages as u64),
        })
        .collect()
}

fn rss_bytes() -> std::io::Result<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| std::io::Error::other("VmRSS missing"))?;
    Ok(kib * 1024)
}

fn extension_bytes(path: &Path, extension: &str) -> std::io::Result<u64> {
    fs::read_dir(path)?.try_fold(0, |total, entry| {
        let entry = entry?;
        Ok(total
            + if entry
                .path()
                .extension()
                .is_some_and(|value| value == extension)
            {
                entry.metadata()?.len()
            } else {
                0
            })
    })
}
