//! Failure containment and immediate-recovery coverage for command invocations.

use runtrue_wasm_runtime::{
    CancellationToken, CommandInput, Error, InvocationState, Program, RunningCommand, Runtime,
    RuntimeConfig, RuntimeLimits,
};
use std::time::{Duration, Instant};

const WATCHDOG_INTERVAL: Duration = Duration::from_millis(1);
const COMPLETION_DEADLINE: Duration = Duration::from_secs(2);
const OVERSIZED_OUTPUT: &[u8] = include_bytes!("fixtures/oversized-output.component.wasm");

#[tokio::test]
async fn guest_trap_is_scoped_to_one_store_and_the_runtime_recovers() {
    let runtime = bounded_runtime(RuntimeLimits::default());
    let trapped = runtime
        .load_bytes(trapping_command())
        .expect("trapping command");

    let error = trapped
        .run(CommandInput::default())
        .await
        .expect_err("guest must trap");
    assert!(matches!(error, Error::Execution(_)), "{error:?}");

    assert_healthy(&runtime).await;
}

#[tokio::test]
async fn infinite_loop_hits_its_deadline_and_the_runtime_recovers() {
    let runtime = bounded_runtime(RuntimeLimits::default());
    let spinning = runtime
        .load_bytes(spinning_command())
        .expect("spinning command");
    let started = Instant::now();

    let result = tokio::time::timeout(
        COMPLETION_DEADLINE,
        spinning.run(CommandInput::default().with_timeout(Duration::from_millis(20))),
    )
    .await
    .expect("watchdog must stop the invocation");
    assert!(matches!(result, Err(Error::Timeout)), "{result:?}");
    assert!(started.elapsed() < COMPLETION_DEADLINE);

    assert_healthy(&runtime).await;
}

#[tokio::test]
async fn linear_memory_limit_rejects_instantiation_and_the_runtime_recovers() {
    let runtime = bounded_runtime(RuntimeLimits {
        max_memory_bytes: 64 * 1024,
        ..RuntimeLimits::default()
    });
    let oversized = runtime
        .load_bytes(command_with_minimum_memory_pages(2))
        .expect("memory-hungry command");

    let error = oversized
        .run(CommandInput::default())
        .await
        .expect_err("two pages must exceed the one-page limit");
    assert!(matches!(error, Error::Execution(_)), "{error:?}");

    assert_healthy(&runtime).await;
}

#[tokio::test]
async fn oversized_input_is_rejected_before_execution_and_the_runtime_recovers() {
    let runtime = bounded_runtime(RuntimeLimits {
        max_input_bytes: 4,
        ..RuntimeLimits::default()
    });
    let command = runtime.load_bytes(successful_command()).expect("command");

    let error = command
        .run(CommandInput::new(b"12345".to_vec()))
        .await
        .expect_err("input must exceed the configured bound");
    assert!(matches!(error, Error::Limit("input bytes")), "{error:?}");

    assert_success(&command).await;
}

#[tokio::test]
async fn oversized_stdout_is_bounded_and_the_runtime_recovers() {
    let runtime = bounded_runtime(RuntimeLimits {
        max_output_bytes: 64,
        ..RuntimeLimits::default()
    });
    let noisy = runtime
        .load_bytes(OVERSIZED_OUTPUT)
        .expect("output fixture");

    let error = noisy
        .run(CommandInput::default())
        .await
        .expect_err("output must exceed the configured bound");
    assert!(matches!(error, Error::Execution(_)), "{error:?}");

    assert_healthy(&runtime).await;
}

#[tokio::test]
async fn cancellation_interrupts_a_running_guest_and_the_runtime_recovers() {
    let runtime = bounded_runtime(RuntimeLimits::default());
    let spinning = runtime
        .load_bytes(spinning_command())
        .expect("spinning command");
    let running = spinning
        .start(CommandInput::default().with_timeout(Duration::from_secs(1)))
        .expect("running command");

    tokio::task::yield_now().await;
    running.cancel();
    let result = tokio::time::timeout(COMPLETION_DEADLINE, running.wait())
        .await
        .expect("cancellation must stop the invocation");
    assert!(matches!(result, Err(Error::Cancelled)), "{result:?}");

    assert_healthy(&runtime).await;
}

#[tokio::test]
async fn cancellation_releases_a_paused_resident_guest_and_the_runtime_recovers() {
    let runtime = bounded_runtime(RuntimeLimits::default());
    let spinning = runtime
        .load_bytes(spinning_command())
        .expect("spinning command");
    let running = spinning
        .start(CommandInput::default().with_timeout(Duration::from_secs(1)))
        .expect("running command");

    running.pause().expect("pause request");
    wait_for_state(&running, InvocationState::PausedResident).await;
    running.cancel();
    let result = tokio::time::timeout(COMPLETION_DEADLINE, running.wait())
        .await
        .expect("cancellation must release the paused invocation");
    assert!(matches!(result, Err(Error::Cancelled)), "{result:?}");

    assert_healthy(&runtime).await;
}

#[tokio::test]
async fn dropping_a_running_handle_requests_shutdown_without_poisoning_the_runtime() {
    let runtime = bounded_runtime(RuntimeLimits::default());
    let spinning = runtime
        .load_bytes(spinning_command())
        .expect("spinning command");
    let cancellation = CancellationToken::new();
    let mut input = CommandInput::default().with_timeout(Duration::from_secs(1));
    input.cancellation = cancellation.clone();
    let running = spinning.start(input).expect("running command");

    drop(running);
    assert!(
        cancellation.is_cancelled(),
        "dropping the handle must synchronously request cancellation"
    );

    assert_healthy(&runtime).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_failures_do_not_prevent_subsequent_work() {
    let runtime = bounded_runtime(RuntimeLimits::default());
    let trapped = runtime
        .load_bytes(trapping_command())
        .expect("trapping command");
    let spinning = runtime
        .load_bytes(spinning_command())
        .expect("spinning command");
    let mut failures = tokio::task::JoinSet::new();

    for _ in 0..8 {
        let trapped = trapped.clone();
        failures.spawn(async move { trapped.run(CommandInput::default()).await });
        let spinning = spinning.clone();
        failures.spawn(async move {
            spinning
                .run(CommandInput::default().with_timeout(Duration::from_millis(20)))
                .await
        });
    }

    let mut trapped_count = 0;
    let mut timeout_count = 0;
    while let Some(result) = failures.join_next().await {
        match result.expect("invocation task") {
            Err(Error::Execution(_)) => trapped_count += 1,
            Err(Error::Timeout) => timeout_count += 1,
            result => panic!("unexpected failure result: {result:?}"),
        }
    }
    assert_eq!(trapped_count, 8);
    assert_eq!(timeout_count, 8);

    for _ in 0..16 {
        assert_healthy(&runtime).await;
    }
}

fn bounded_runtime(limits: RuntimeLimits) -> Runtime {
    Runtime::new(RuntimeConfig {
        epoch_interval: WATCHDOG_INTERVAL,
        paused_resident_ttl: Duration::from_millis(250),
        limits,
        ..RuntimeConfig::default()
    })
    .expect("runtime")
}

async fn assert_healthy(runtime: &Runtime) {
    let command = runtime
        .load_bytes(successful_command())
        .expect("healthy command");
    assert_success(&command).await;
}

async fn assert_success(command: &Program) {
    let result = tokio::time::timeout(COMPLETION_DEADLINE, command.run(CommandInput::default()))
        .await
        .expect("healthy invocation must complete")
        .expect("healthy invocation");
    assert_eq!(result.exit_code, 0);
}

async fn wait_for_state(running: &RunningCommand, expected: InvocationState) {
    tokio::time::timeout(COMPLETION_DEADLINE, async {
        loop {
            if running.state() == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "invocation did not reach {expected:?}; current state: {:?}",
            running.state()
        )
    });
}

fn successful_command() -> Vec<u8> {
    command_component("i32.const 0", "")
}

fn trapping_command() -> Vec<u8> {
    command_component("unreachable", "")
}

fn spinning_command() -> Vec<u8> {
    command_component("(loop $spin br $spin) unreachable", "")
}

fn command_with_minimum_memory_pages(pages: u32) -> Vec<u8> {
    command_component("i32.const 0", &format!("(memory {pages})"))
}

fn command_component(run_body: &str, module_fields: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"
        (component
          (type $run-func (func (result (result))))
          (type $run-interface (instance
            (export "run" (func (type $run-func)))))
          (core module $command
            {module_fields}
            (func (export "run") (result i32)
              {run_body}))
          (core instance $command-instance (instantiate $command))
          (func $run (type $run-func)
            (canon lift (core func $command-instance "run")))
          (instance $run-instance
            (export "run" (func $run)))
          (export "wasi:cli/run@0.2.12"
            (instance $run-instance)))
        "#
    ))
    .expect("valid command component")
}
