//! Standard WASI HTTP worker residency integration test.

use runtrue_wasm_runtime::{
    HttpRequest, HttpServiceConfig, HttpServiceState, PackageTier, Runtime, WasiProfile,
};
use std::time::Duration;

const HTTP_COMPONENT: &[u8] = include_bytes!("fixtures/p3-http-hello.component.wasm");

#[tokio::test]
async fn reuses_then_evicts_idle_http_worker() {
    let runtime = Runtime::with_defaults().expect("runtime");
    let program = runtime.load_bytes(HTTP_COMPONENT).expect("component");
    let service = program
        .http_service(HttpServiceConfig {
            idle_worker_ttl: Duration::from_millis(20),
            ..HttpServiceConfig::default()
        })
        .await
        .expect("HTTP service");

    assert_eq!(service.profile(), WasiProfile::Http0_3);
    assert_eq!(service.state(), HttpServiceState::NoResidentWorker);
    let first = service
        .handle(HttpRequest::new(
            "POST",
            "http://localhost/tools/call",
            b"{}",
        ))
        .await
        .expect("first response");
    assert_eq!(first.status, 200);
    assert_eq!(first.body, b"Hello, WASI!");
    assert!(first.worker_created);

    tokio::task::yield_now().await;
    assert_eq!(service.state(), HttpServiceState::PausedResident);
    let second = service
        .handle(HttpRequest::new(
            "POST",
            "http://localhost/tools/call",
            b"{}",
        ))
        .await
        .expect("resident response");
    assert!(!second.worker_created);
    assert_eq!(service.metrics().workers_created, 1);

    tokio::time::timeout(Duration::from_secs(1), async {
        while service.metrics().idle_evictions == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("idle eviction");
    assert_eq!(service.state(), HttpServiceState::NoResidentWorker);
    assert_eq!(service.package_tier(), PackageTier::Warmish);

    let restarted = service
        .handle(HttpRequest::new("GET", "http://localhost/", Vec::new()))
        .await
        .expect("warmish restart");
    assert!(restarted.worker_created);
    assert_eq!(restarted.package_tier, PackageTier::Warmish);
    assert_eq!(service.metrics().workers_created, 2);
}
