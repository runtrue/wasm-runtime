//! Reproducible cold, disk AOT, warmish, and warm command benchmark.

use runtrue_wasm_runtime::{
    AotAuthenticationKey, CommandInput, DiskCacheConfig, PackageTier, Runtime, RuntimeConfig,
};
use serde::Serialize;
use std::{hint::black_box, time::Instant};
use tempfile::TempDir;

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    runtime_version: &'static str,
    wasmtime_version: &'static str,
    host_os: &'static str,
    host_arch: &'static str,
    wasi: String,
    iterations: usize,
    states: Vec<StateReport>,
}

#[derive(Serialize)]
struct StateReport {
    state: &'static str,
    samples: Vec<Sample>,
    p50: Sample,
    p95: Sample,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[allow(clippy::struct_field_names)] // Unit suffixes keep exported JSON unambiguous.
struct Sample {
    runtime_init_ns: u64,
    prepare_ns: u64,
    instantiate_ns: u64,
    execute_ns: u64,
    suspended_ns: u64,
    active_execute_ns: u64,
    call_total_ns: u64,
    harness_total_ns: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let wasi = arguments.next().unwrap_or_else(|| "0.3".to_owned());
    let iterations = arguments
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(100);
    if arguments.next().is_some() || !matches!(wasi.as_str(), "0.2" | "0.3") || iterations == 0 {
        return Err("usage: tier_benchmark [0.2|0.3] [positive-iterations]".into());
    }
    let component = if wasi == "0.3" {
        p3_command()
    } else {
        p2_command("target")
    };
    let tokio = tokio::runtime::Runtime::new()?;
    let states = vec![
        cold(&tokio, &component, iterations)?,
        disk_aot(&tokio, &component, iterations)?,
        warmish(&tokio, &component, iterations)?,
        warm(&tokio, &component, iterations)?,
    ];
    println!(
        "{}",
        serde_json::to_string_pretty(&Report {
            schema: "runtrue-wasm-tier-benchmark-v1",
            runtime_version: env!("CARGO_PKG_VERSION"),
            wasmtime_version: "46.0.1",
            host_os: std::env::consts::OS,
            host_arch: std::env::consts::ARCH,
            wasi,
            iterations,
            states,
        })?
    );
    Ok(())
}

fn cold(
    tokio: &tokio::runtime::Runtime,
    component: &[u8],
    iterations: usize,
) -> Result<StateReport, Box<dyn std::error::Error>> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let harness = Instant::now();
        let runtime_started = Instant::now();
        let runtime = Runtime::with_defaults()?;
        let runtime_init_ns = nanos(runtime_started.elapsed());
        let program = runtime.load_bytes(component.to_vec())?;
        let output = tokio.block_on(program.run(CommandInput::default()))?;
        assert_eq!(output.measurement.prepared_from, PackageTier::Cold);
        samples.push(sample(runtime_init_ns, &output, harness));
    }
    Ok(report("cold", samples))
}

fn disk_aot(
    tokio: &tokio::runtime::Runtime,
    component: &[u8],
    iterations: usize,
) -> Result<StateReport, Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let config = disk_config(&directory);
    {
        let runtime = Runtime::new(config.clone())?;
        let program = runtime.load_bytes(component.to_vec())?;
        tokio.block_on(program.prepare())?;
    }
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let harness = Instant::now();
        let runtime_started = Instant::now();
        let runtime = Runtime::new(config.clone())?;
        let runtime_init_ns = nanos(runtime_started.elapsed());
        let program = runtime.load_bytes(component.to_vec())?;
        let output = tokio.block_on(program.run(CommandInput::default()))?;
        assert_eq!(output.measurement.prepared_from, PackageTier::DiskAot);
        samples.push(sample(runtime_init_ns, &output, harness));
    }
    Ok(report("disk-aot", samples))
}

fn warmish(
    tokio: &tokio::runtime::Runtime,
    component: &[u8],
    iterations: usize,
) -> Result<StateReport, Box<dyn std::error::Error>> {
    let config = RuntimeConfig {
        max_warm_components: 1,
        max_warmish_entries: 4,
        ..RuntimeConfig::default()
    };
    let runtime = Runtime::new(config)?;
    let target = runtime.load_bytes(component.to_vec())?;
    let evictor = runtime.load_bytes(p2_command("evictor"))?;
    tokio.block_on(target.prepare())?;
    tokio.block_on(evictor.prepare())?;
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        assert_eq!(target.tier(), PackageTier::Warmish);
        let harness = Instant::now();
        let output = tokio.block_on(target.run(CommandInput::default()))?;
        assert_eq!(output.measurement.prepared_from, PackageTier::Warmish);
        samples.push(sample(0, &output, harness));
        tokio.block_on(evictor.prepare())?;
    }
    Ok(report("warmish", samples))
}

fn warm(
    tokio: &tokio::runtime::Runtime,
    component: &[u8],
    iterations: usize,
) -> Result<StateReport, Box<dyn std::error::Error>> {
    let runtime = Runtime::with_defaults()?;
    let program = runtime.load_bytes(component.to_vec())?;
    tokio.block_on(program.prepare())?;
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let harness = Instant::now();
        let output = tokio.block_on(program.run(CommandInput::default()))?;
        assert_eq!(output.measurement.prepared_from, PackageTier::Warm);
        samples.push(sample(0, &output, harness));
    }
    Ok(report("warm", samples))
}

fn sample(
    runtime_init_ns: u64,
    output: &runtrue_wasm_runtime::CommandOutput,
    harness: Instant,
) -> Sample {
    black_box(&output.stdout);
    Sample {
        runtime_init_ns,
        prepare_ns: nanos(output.measurement.phases.prepare),
        instantiate_ns: nanos(output.measurement.phases.instantiate),
        execute_ns: nanos(output.measurement.phases.execute),
        suspended_ns: nanos(output.measurement.phases.suspended),
        active_execute_ns: nanos(output.measurement.phases.active_execute),
        call_total_ns: nanos(output.measurement.phases.total),
        harness_total_ns: nanos(harness.elapsed()),
    }
}

fn report(state: &'static str, samples: Vec<Sample>) -> StateReport {
    StateReport {
        state,
        p50: percentile(&samples, 50),
        p95: percentile(&samples, 95),
        samples,
    }
}

fn percentile(samples: &[Sample], percentile: usize) -> Sample {
    let field = |select: fn(&Sample) -> u64| {
        let mut values = samples.iter().map(select).collect::<Vec<_>>();
        values.sort_unstable();
        values[((values.len() * percentile).div_ceil(100)).saturating_sub(1)]
    };
    Sample {
        runtime_init_ns: field(|sample| sample.runtime_init_ns),
        prepare_ns: field(|sample| sample.prepare_ns),
        instantiate_ns: field(|sample| sample.instantiate_ns),
        execute_ns: field(|sample| sample.execute_ns),
        suspended_ns: field(|sample| sample.suspended_ns),
        active_execute_ns: field(|sample| sample.active_execute_ns),
        call_total_ns: field(|sample| sample.call_total_ns),
        harness_total_ns: field(|sample| sample.harness_total_ns),
    }
}

fn disk_config(directory: &TempDir) -> RuntimeConfig {
    RuntimeConfig {
        disk_cache: Some(DiskCacheConfig::new(
            directory.path(),
            AotAuthenticationKey::new([17; 32]),
        )),
        ..RuntimeConfig::default()
    }
}

fn nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn p2_command(marker: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(component
          (type $run-func (func (result (result))))
          (type $run-interface (instance (export "run" (func (type $run-func)))))
          (core module $command
            (func (export "run") (result i32) i32.const 0)
            (func (export "{marker}")))
          (core instance $command-instance (instantiate $command))
          (func $run (type $run-func) (canon lift (core func $command-instance "run")))
          (instance $run-instance (export "run" (func $run)))
          (export "wasi:cli/run@0.2.12" (instance $run-instance)))"#
    ))
    .expect("valid benchmark component")
}

fn p3_command() -> Vec<u8> {
    wat::parse_str(
        r#"(component
          (type $run-func (func async (result (result))))
          (type $run-interface (instance (export "run" (func (type $run-func)))))
          (core module $command
            (import "[export]wasi:cli/run@0.3.0" "[task-return]run"
              (func $task-return (param i32)))
            (func (export "[async-lift-stackful]wasi:cli/run@0.3.0#run")
              i32.const 0 call $task-return))
          (core func $task-return (canon task.return (result (result))))
          (core instance $task-return-instance
            (export "[task-return]run" (func $task-return)))
          (core instance $command-instance
            (instantiate $command
              (with "[export]wasi:cli/run@0.3.0" (instance $task-return-instance))))
          (func $run (type $run-func)
            (canon lift
              (core func $command-instance "[async-lift-stackful]wasi:cli/run@0.3.0#run")
              async))
          (instance $run-instance (export "run" (func $run)))
          (export "wasi:cli/run@0.3.0" (instance $run-instance)))"#,
    )
    .expect("valid benchmark component")
}
