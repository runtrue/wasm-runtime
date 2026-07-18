//! Reproducible WASI HTTP cold, paused-resident, warmish, and throughput benchmark.

use runtrue_wasm_runtime::{
    AotAuthenticationKey, DiskCacheConfig, HttpRequest, HttpService, HttpServiceConfig,
    HttpServiceState, PackageTier, Runtime, RuntimeConfig,
};
use serde::Serialize;
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

const COMPONENT: &[u8] = include_bytes!("../tests/fixtures/p3-http-hello.component.wasm");

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    runtime_version: &'static str,
    wasmtime_version: &'static str,
    host_os: &'static str,
    host_arch: &'static str,
    iterations: usize,
    cold: Distribution,
    disk_aot: Distribution,
    disk_aot_artifact_bytes: u64,
    paused_resident: Distribution,
    warmish_restart: Distribution,
    throughput: Vec<Throughput>,
}

#[derive(Serialize)]
struct Distribution {
    samples: Vec<Sample>,
    p50: Sample,
    p95: Sample,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[allow(clippy::struct_field_names)] // Unit suffixes keep exported JSON unambiguous.
struct Sample {
    runtime_init_ns: u64,
    service_prepare_ns: u64,
    service_start_total_ns: u64,
    request_ns: u64,
    harness_total_ns: u64,
}

#[derive(Serialize)]
struct Throughput {
    concurrency: usize,
    requests: usize,
    elapsed_ns: u64,
    requests_per_second: u64,
    latency_p50_ns: u64,
    latency_p95_ns: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let iterations = arguments
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(20);
    let throughput_requests = arguments
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1_000);
    if arguments.next().is_some() || iterations == 0 || throughput_requests == 0 {
        return Err(
            "usage: http_benchmark [positive-iterations] [positive-throughput-requests]".into(),
        );
    }

    let (disk_aot, disk_aot_artifact_bytes) = disk_aot(iterations).await?;
    let report = Report {
        schema: "runtrue-wasm-http-benchmark-v2",
        runtime_version: env!("CARGO_PKG_VERSION"),
        wasmtime_version: runtrue_wasm_runtime::WASMTIME_VERSION,
        host_os: std::env::consts::OS,
        host_arch: std::env::consts::ARCH,
        iterations,
        cold: cold(iterations).await?,
        disk_aot,
        disk_aot_artifact_bytes,
        paused_resident: paused_resident(iterations).await?,
        warmish_restart: warmish_restart(iterations).await?,
        throughput: vec![
            throughput(1, throughput_requests).await?,
            throughput(8, throughput_requests).await?,
            throughput(32, throughput_requests).await?,
        ],
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn disk_aot(iterations: usize) -> Result<(Distribution, u64), Box<dyn std::error::Error>> {
    let directory = tempfile::TempDir::new()?;
    let config = RuntimeConfig {
        disk_cache: Some(DiskCacheConfig::new(
            directory.path(),
            AotAuthenticationKey::new([41; 32]),
        )),
        ..RuntimeConfig::default()
    };
    {
        let runtime = Runtime::new(config.clone())?;
        let program = runtime.load_bytes(COMPONENT)?;
        program.http_service(service_config()).await?;
    }
    let artifact_bytes = directory_bytes(directory.path(), "aot")?;
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let harness = Instant::now();
        let runtime_started = Instant::now();
        let runtime = Runtime::new(config.clone())?;
        let program = runtime.load_bytes(COMPONENT)?;
        assert_eq!(program.tier(), PackageTier::DiskAot);
        let runtime_init_ns = nanos(runtime_started.elapsed());
        let service = program.http_service(service_config()).await?;
        assert_eq!(service.startup_from(), PackageTier::DiskAot);
        let response = service.handle(tool_request()).await?;
        samples.push(Sample {
            runtime_init_ns,
            service_prepare_ns: nanos(service.startup_prepare()),
            service_start_total_ns: nanos(service.startup_total()),
            request_ns: nanos(response.elapsed),
            harness_total_ns: nanos(harness.elapsed()),
        });
    }
    Ok((distribution(samples), artifact_bytes))
}

fn directory_bytes(path: &Path, extension: &str) -> std::io::Result<u64> {
    fs::read_dir(path)?.try_fold(0, |total, entry| {
        let entry = entry?;
        let bytes = if entry
            .path()
            .extension()
            .is_some_and(|value| value == extension)
        {
            entry.metadata()?.len()
        } else {
            0
        };
        Ok(total + bytes)
    })
}

async fn cold(iterations: usize) -> Result<Distribution, Box<dyn std::error::Error>> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let harness = Instant::now();
        let runtime_started = Instant::now();
        let (runtime, program) = tokio::task::spawn_blocking(|| {
            let runtime = Runtime::with_defaults()?;
            let program = runtime.load_bytes(COMPONENT)?;
            Ok::<_, runtrue_wasm_runtime::Error>((runtime, program))
        })
        .await??;
        let runtime_init_ns = nanos(runtime_started.elapsed());
        let service = program.http_service(service_config()).await?;
        assert_eq!(service.startup_from(), PackageTier::Cold);
        let response = service.handle(tool_request()).await?;
        assert!(response.worker_created);
        samples.push(Sample {
            runtime_init_ns,
            service_prepare_ns: nanos(service.startup_prepare()),
            service_start_total_ns: nanos(service.startup_total()),
            request_ns: nanos(response.elapsed),
            harness_total_ns: nanos(harness.elapsed()),
        });
        drop(runtime);
    }
    Ok(distribution(samples))
}

async fn paused_resident(iterations: usize) -> Result<Distribution, Box<dyn std::error::Error>> {
    let service = ready_service(Duration::from_secs(30)).await?;
    service.handle(tool_request()).await?;
    tokio::task::yield_now().await;
    assert_eq!(service.state(), HttpServiceState::PausedResident);
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let harness = Instant::now();
        let response = service.handle(tool_request()).await?;
        assert!(!response.worker_created);
        samples.push(Sample {
            request_ns: nanos(response.elapsed),
            harness_total_ns: nanos(harness.elapsed()),
            ..Sample::default()
        });
    }
    Ok(distribution(samples))
}

async fn warmish_restart(iterations: usize) -> Result<Distribution, Box<dyn std::error::Error>> {
    let service = ready_service(Duration::from_millis(5)).await?;
    service.handle(tool_request()).await?;
    let mut samples = Vec::with_capacity(iterations);
    for expected_evictions in 1..=iterations {
        wait_for_evictions(&service, expected_evictions as u64).await?;
        assert_eq!(service.package_tier(), PackageTier::Warmish);
        let harness = Instant::now();
        let response = service.handle(tool_request()).await?;
        assert_eq!(response.package_tier, PackageTier::Warmish);
        assert!(response.worker_created);
        samples.push(Sample {
            request_ns: nanos(response.elapsed),
            harness_total_ns: nanos(harness.elapsed()),
            ..Sample::default()
        });
    }
    Ok(distribution(samples))
}

async fn throughput(
    concurrency: usize,
    requests: usize,
) -> Result<Throughput, Box<dyn std::error::Error>> {
    let service = ready_service(Duration::from_secs(30)).await?;
    service.handle(tool_request()).await?;
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(requests);
    for offset in (0..requests).step_by(concurrency) {
        let count = concurrency.min(requests - offset);
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..count {
            let service = service.clone();
            set.spawn(async move { service.handle(tool_request()).await });
        }
        while let Some(response) = set.join_next().await {
            latencies.push(nanos(response??.elapsed));
        }
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();
    Ok(Throughput {
        concurrency,
        requests,
        elapsed_ns: nanos(elapsed),
        requests_per_second: u64::try_from(
            (requests as u128 * 1_000_000_000) / elapsed.as_nanos().max(1),
        )
        .unwrap_or(u64::MAX),
        latency_p50_ns: percentile_value(&latencies, 50),
        latency_p95_ns: percentile_value(&latencies, 95),
    })
}

async fn ready_service(
    idle_worker_ttl: Duration,
) -> Result<HttpService, Box<dyn std::error::Error>> {
    let runtime = Runtime::with_defaults()?;
    let program = runtime.load_bytes(COMPONENT)?;
    Ok(program
        .http_service(HttpServiceConfig {
            idle_worker_ttl,
            ..service_config()
        })
        .await?)
}

fn service_config() -> HttpServiceConfig {
    HttpServiceConfig {
        request_timeout: Duration::from_secs(5),
        ..HttpServiceConfig::default()
    }
}

fn tool_request() -> HttpRequest {
    HttpRequest::new(
        "POST",
        "http://localhost/tools/call",
        br#"{"name":"echo","arguments":{"text":"hello"}}"#,
    )
    .with_header("content-type", "application/json")
}

async fn wait_for_evictions(
    service: &HttpService,
    expected: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.metrics().idle_evictions < expected {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}

fn distribution(samples: Vec<Sample>) -> Distribution {
    Distribution {
        p50: percentile_sample(&samples, 50),
        p95: percentile_sample(&samples, 95),
        samples,
    }
}

fn percentile_sample(samples: &[Sample], percentile: usize) -> Sample {
    let field = |select: fn(&Sample) -> u64| {
        let mut values = samples.iter().map(select).collect::<Vec<_>>();
        values.sort_unstable();
        percentile_value(&values, percentile)
    };
    Sample {
        runtime_init_ns: field(|sample| sample.runtime_init_ns),
        service_prepare_ns: field(|sample| sample.service_prepare_ns),
        service_start_total_ns: field(|sample| sample.service_start_total_ns),
        request_ns: field(|sample| sample.request_ns),
        harness_total_ns: field(|sample| sample.harness_total_ns),
    }
}

fn percentile_value(values: &[u64], percentile: usize) -> u64 {
    values[((values.len() * percentile).div_ceil(100)).saturating_sub(1)]
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
