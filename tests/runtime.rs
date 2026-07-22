//! Integration coverage for standard command profiles and preparation tiers.

use runtrue_wasm_runtime::{
    AotAuthenticationKey, CommandInput, DiskCacheConfig, Error, InvocationState, PackageTier,
    RunningCommand, Runtime, RuntimeConfig, WasiProfile, WasiVersion,
};
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn cold_promotes_to_warm_and_calls_with_a_fresh_store() {
    let runtime = Runtime::with_defaults().unwrap();
    let program = runtime.load_bytes(p2_command("first")).unwrap();
    assert_eq!(program.tier(), PackageTier::Cold);

    let tokio = tokio::runtime::Runtime::new().unwrap();
    let first = tokio
        .block_on(program.run(CommandInput::new(b"ignored".to_vec())))
        .unwrap();
    assert_eq!(first.exit_code, 0);
    assert_eq!(first.wasi_version, WasiVersion::V0_2);
    assert_eq!(first.measurement.prepared_from, PackageTier::Cold);
    assert_eq!(program.tier(), PackageTier::Warm);

    let second = tokio
        .block_on(program.run(CommandInput::default()))
        .unwrap();
    assert_eq!(second.measurement.prepared_from, PackageTier::Warm);
}

#[test]
fn warm_eviction_demotes_to_warmish() {
    let config = RuntimeConfig {
        max_warm_components: 1,
        max_warmish_entries: 2,
        ..RuntimeConfig::default()
    };
    let runtime = Runtime::new(config).unwrap();
    let first = runtime.load_bytes(p2_command("first")).unwrap();
    let second = runtime.load_bytes(p2_command("second")).unwrap();
    let tokio = tokio::runtime::Runtime::new().unwrap();
    tokio.block_on(first.prepare()).unwrap();
    tokio.block_on(second.prepare()).unwrap();
    assert_eq!(first.tier(), PackageTier::Warmish);
    assert_eq!(second.tier(), PackageTier::Warm);

    let output = tokio.block_on(first.run(CommandInput::default())).unwrap();
    assert_eq!(output.measurement.prepared_from, PackageTier::Warmish);
}

#[test]
fn authenticated_disk_aot_survives_a_fresh_runtime() {
    let directory = TempDir::new().unwrap();
    let config = RuntimeConfig {
        disk_cache: Some(DiskCacheConfig::new(
            directory.path(),
            AotAuthenticationKey::new([7; 32]),
        )),
        ..RuntimeConfig::default()
    };
    let component = p2_command("disk");
    let tokio = tokio::runtime::Runtime::new().unwrap();

    {
        let runtime = Runtime::new(config.clone()).unwrap();
        let program = runtime.load_bytes(component.clone()).unwrap();
        tokio.block_on(program.prepare()).unwrap();
        assert_eq!(program.tier(), PackageTier::Warm);
    }

    let runtime = Runtime::new(config).unwrap();
    let program = runtime.load_bytes(component).unwrap();
    assert_eq!(program.tier(), PackageTier::DiskAot);
    let output = tokio
        .block_on(program.run(CommandInput::default()))
        .unwrap();
    assert_eq!(output.measurement.prepared_from, PackageTier::DiskAot);
    assert_eq!(output.exit_code, 0);
}

#[test]
fn wasi_0_3_command_is_the_primary_accepted_profile() {
    let runtime = Runtime::with_defaults().unwrap();
    let program = runtime.load_bytes(p3_command()).unwrap();
    let tokio = tokio::runtime::Runtime::new().unwrap();
    tokio.block_on(program.prepare()).unwrap();
    assert_eq!(program.tier(), PackageTier::Warm);
    let output = tokio
        .block_on(program.run(CommandInput::default()))
        .unwrap();
    assert_eq!(output.wasi_version, WasiVersion::V0_3);
    assert_eq!(output.exit_code, 0);
}

#[test]
fn synchronous_embedders_can_discover_and_run_a_standard_profile() {
    let runtime = Runtime::with_defaults().unwrap();
    let program = runtime.load_bytes(p3_command()).unwrap();
    assert_eq!(program.profile_blocking().unwrap(), WasiProfile::Cli0_3);
    let output = program.run_blocking(CommandInput::default()).unwrap();
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.wasi_version, WasiVersion::V0_3);
}

#[test]
fn paused_invocation_resumes_the_same_resident_execution() {
    let config = RuntimeConfig {
        paused_resident_ttl: Duration::from_millis(250),
        epoch_interval: Duration::from_millis(1),
        ..RuntimeConfig::default()
    };
    let runtime = Runtime::new(config).unwrap();
    let program = runtime.load_bytes(p2_spinning_command()).unwrap();
    let tokio = tokio::runtime::Runtime::new().unwrap();

    tokio.block_on(async {
        program.prepare().await.unwrap();
        let running = program
            .start(CommandInput::default().with_timeout(Duration::from_secs(1)))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        running.pause().unwrap();
        wait_for_state(&running, InvocationState::PausedResident).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        running.resume().unwrap();
        assert_eq!(running.state(), InvocationState::Running);
        tokio::time::sleep(Duration::from_millis(5)).await;
        running.cancel();
        assert!(matches!(running.wait().await, Err(Error::Cancelled)));
    });
}

#[test]
fn idle_eviction_drops_the_store_and_demotes_the_package() {
    let config = RuntimeConfig {
        paused_resident_ttl: Duration::from_millis(20),
        epoch_interval: Duration::from_millis(1),
        ..RuntimeConfig::default()
    };
    let runtime = Runtime::new(config).unwrap();
    let program = runtime.load_bytes(p2_spinning_command()).unwrap();
    let tokio = tokio::runtime::Runtime::new().unwrap();

    tokio.block_on(async {
        program.prepare().await.unwrap();
        let running = program
            .start(CommandInput::default().with_timeout(Duration::from_secs(1)))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        running.pause().unwrap();
        wait_for_state(&running, InvocationState::PausedResident).await;
        assert!(matches!(running.wait().await, Err(Error::IdleEvicted)));
        assert_eq!(program.tier(), PackageTier::Warmish);
    });
}

async fn wait_for_state(running: &RunningCommand, expected: InvocationState) {
    for _ in 0..100 {
        if running.state() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!(
        "invocation did not reach {expected:?}; current state: {:?}",
        running.state()
    );
}

fn p2_command(marker: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"
        (component
          (type $run-func (func (result (result))))
          (type $run-interface (instance
            (export "run" (func (type $run-func)))))
          (core module $command
            (func (export "run") (result i32) i32.const 0)
            (func (export "{marker}")))
          (core instance $command-instance (instantiate $command))
          (func $run (type $run-func)
            (canon lift (core func $command-instance "run")))
          (instance $run-instance
            (export "run" (func $run)))
          (export "wasi:cli/run@0.2.12"
            (instance $run-instance)))
        "#
    ))
    .unwrap()
}

fn p3_command() -> Vec<u8> {
    wat::parse_str(
        r#"
        (component
          (type $run-func (func async (result (result))))
          (type $run-interface (instance
            (export "run" (func (type $run-func)))))
          (core module $command
            (import "[export]wasi:cli/run@0.3.0" "[task-return]run"
              (func $task-return (param i32)))
            (func (export "[async-lift-stackful]wasi:cli/run@0.3.0#run")
              i32.const 0
              call $task-return))
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
          (instance $run-instance
            (export "run" (func $run)))
          (export "wasi:cli/run@0.3.0"
            (instance $run-instance)))
        "#,
    )
    .unwrap()
}

fn p2_spinning_command() -> Vec<u8> {
    wat::parse_str(
        r#"
        (component
          (type $run-func (func (result (result))))
          (type $run-interface (instance
            (export "run" (func (type $run-func)))))
          (core module $command
            (func (export "run") (result i32)
              (loop $spin
                br $spin)
              unreachable))
          (core instance $command-instance (instantiate $command))
          (func $run (type $run-func)
            (canon lift (core func $command-instance "run")))
          (instance $run-instance
            (export "run" (func $run)))
          (export "wasi:cli/run@0.2.12"
            (instance $run-instance)))
        "#,
    )
    .unwrap()
}
