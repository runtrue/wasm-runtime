//! Reproducible cooperative pause, resume, and idle-eviction benchmark.

use runtrue_wasm_runtime::{
    CommandInput, Error, InvocationState, PackageTier, RunningCommand, Runtime, RuntimeConfig,
};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    runtime_version: &'static str,
    wasmtime_version: &'static str,
    host_os: &'static str,
    host_arch: &'static str,
    iterations: usize,
    pause_ack_ns: Percentiles,
    resume_call_ns: Percentiles,
    idle_eviction: IdleEviction,
}

#[derive(Serialize)]
struct Percentiles {
    p50: u64,
    p95: u64,
}

#[derive(Serialize)]
struct IdleEviction {
    configured_ttl_ns: u64,
    observed_ns: u64,
    retained_tier: PackageTier,
    rss_before_kib: Option<u64>,
    rss_paused_kib: Option<u64>,
    rss_after_eviction_kib: Option<u64>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = std::env::args()
        .nth(1)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(100);
    if iterations == 0 || std::env::args().nth(2).is_some() {
        return Err("usage: pause_benchmark [positive-iterations]".into());
    }

    let runtime = Runtime::new(RuntimeConfig {
        paused_resident_ttl: Duration::from_secs(1),
        epoch_interval: Duration::from_millis(1),
        ..RuntimeConfig::default()
    })?;
    let program = runtime.load_bytes(spinning_command())?;
    program.prepare().await?;
    let mut pause_samples = Vec::with_capacity(iterations);
    let mut resume_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let running = program.start(long_input())?;
        tokio::task::yield_now().await;
        let pause_started = Instant::now();
        running.pause()?;
        wait_until_paused(&running).await?;
        pause_samples.push(nanos(pause_started.elapsed()));
        let resume_started = Instant::now();
        running.resume()?;
        resume_samples.push(nanos(resume_started.elapsed()));
        running.cancel();
        assert!(matches!(running.wait().await, Err(Error::Cancelled)));
    }

    let idle_eviction = measure_idle_eviction().await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            schema: "runtrue-wasm-pause-benchmark-v1",
            runtime_version: env!("CARGO_PKG_VERSION"),
            wasmtime_version: runtrue_wasm_runtime::WASMTIME_VERSION,
            host_os: std::env::consts::OS,
            host_arch: std::env::consts::ARCH,
            iterations,
            pause_ack_ns: percentiles(&mut pause_samples),
            resume_call_ns: percentiles(&mut resume_samples),
            idle_eviction,
        })?
    );
    Ok(())
}

async fn measure_idle_eviction() -> Result<IdleEviction, Box<dyn std::error::Error>> {
    let ttl = Duration::from_millis(20);
    let runtime = Runtime::new(RuntimeConfig {
        paused_resident_ttl: ttl,
        epoch_interval: Duration::from_millis(1),
        ..RuntimeConfig::default()
    })?;
    let program = runtime.load_bytes(spinning_command())?;
    program.prepare().await?;
    let rss_before_kib = resident_set_kib();
    let running = program.start(long_input())?;
    tokio::task::yield_now().await;
    let eviction_started = Instant::now();
    running.pause()?;
    wait_until_paused(&running).await?;
    let rss_paused_kib = resident_set_kib();
    assert!(matches!(running.wait().await, Err(Error::IdleEvicted)));
    let observed_ns = nanos(eviction_started.elapsed());
    let rss_after_eviction_kib = resident_set_kib();
    Ok(IdleEviction {
        configured_ttl_ns: nanos(ttl),
        observed_ns,
        retained_tier: program.tier(),
        rss_before_kib,
        rss_paused_kib,
        rss_after_eviction_kib,
    })
}

async fn wait_until_paused(running: &RunningCommand) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match running.state() {
            InvocationState::PausedResident => return Ok(()),
            InvocationState::Evicted => return Err(Error::IdleEvicted),
            InvocationState::Finished => {
                return Err(Error::InvalidState("invocation finished before pausing"));
            }
            InvocationState::Running | InvocationState::PauseRequested => {}
            _ => return Err(Error::InvalidState("unknown invocation state")),
        }
        if Instant::now() >= deadline {
            return Err(Error::InvalidState("pause acknowledgement timed out"));
        }
        tokio::task::yield_now().await;
    }
}

fn long_input() -> CommandInput {
    CommandInput::default().with_timeout(Duration::from_secs(5))
}

fn percentiles(values: &mut [u64]) -> Percentiles {
    values.sort_unstable();
    Percentiles {
        p50: percentile(values, 50),
        p95: percentile(values, 95),
    }
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    values[((values.len() * percentile).div_ceil(100)).saturating_sub(1)]
}

fn resident_set_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn spinning_command() -> Vec<u8> {
    wat::parse_str(
        r#"(component
          (type $run-func (func (result (result))))
          (type $run-interface (instance (export "run" (func (type $run-func)))))
          (core module $command
            (func (export "run") (result i32)
              (loop $spin br $spin)
              unreachable))
          (core instance $command-instance (instantiate $command))
          (func $run (type $run-func) (canon lift (core func $command-instance "run")))
          (instance $run-instance (export "run" (func $run)))
          (export "wasi:cli/run@0.2.12" (instance $run-instance)))"#,
    )
    .expect("valid spinning benchmark component")
}
