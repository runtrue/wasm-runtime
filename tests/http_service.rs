//! Standard WASI HTTP worker residency integration test.

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use runtrue_wasm_runtime::{
    Error, HttpRequest, HttpServiceConfig, HttpServiceState, PackageTier, Runtime, RuntimeConfig,
    RuntimeLimits, WasiProfile,
};
use std::time::Duration;

const HTTP_COMPONENT: &[u8] = include_bytes!("fixtures/p3-http-hello.component.wasm");

#[tokio::test]
async fn streaming_path_preserves_http_parts_and_completes_metrics() {
    let runtime = Runtime::with_defaults().expect("runtime");
    let program = runtime.load_bytes(HTTP_COMPONENT).expect("component");
    let service = program
        .http_service(HttpServiceConfig::default())
        .await
        .expect("HTTP service");
    let request = http::Request::builder()
        .method("POST")
        .uri("http://localhost/tools/call")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(b"{}")))
        .expect("request");

    let response = service
        .handle_streaming(request)
        .await
        .expect("streaming response");
    assert_eq!(response.status(), 200);
    let metadata = response.body().metadata();
    assert_eq!(metadata.request_id, 1);
    assert_eq!(metadata.package_tier, PackageTier::Warm);
    assert!(metadata.worker_created);
    assert!(!metadata.headers_elapsed.is_zero());
    assert_eq!(service.metrics().in_flight, 1);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    assert_eq!(body, b"Hello, WASI!".as_slice());
    assert_eq!(service.metrics().in_flight, 0);
    assert_eq!(service.metrics().completed_requests, 1);
}

#[tokio::test]
async fn streaming_path_enforces_input_and_output_limits() {
    let runtime = Runtime::new(RuntimeConfig {
        limits: RuntimeLimits {
            max_input_bytes: 1,
            max_output_bytes: 5,
            ..RuntimeLimits::default()
        },
        ..RuntimeConfig::default()
    })
    .expect("runtime");
    let service = runtime
        .load_bytes(HTTP_COMPONENT)
        .expect("component")
        .http_service(HttpServiceConfig::default())
        .await
        .expect("HTTP service");

    let oversized = http::Request::builder()
        .uri("http://localhost/")
        .body(Full::new(Bytes::from_static(b"{}")))
        .expect("request");
    let input_error = service
        .handle_streaming(oversized)
        .await
        .expect_err("oversized input");
    assert!(matches!(input_error, Error::Limit("input bytes")));

    let request = http::Request::builder()
        .uri("http://localhost/")
        .body(Full::new(Bytes::new()))
        .expect("request");
    let response = service
        .handle_streaming(request)
        .await
        .expect("response headers");
    let output_error = response
        .into_body()
        .collect()
        .await
        .expect_err("oversized output");
    assert!(matches!(output_error, Error::Limit("output bytes")));
    assert_eq!(service.metrics().in_flight, 0);
    assert_eq!(service.metrics().completed_requests, 0);
}

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
        .handle_streaming(
            http::Request::builder()
                .uri("http://localhost/")
                .body(Full::new(Bytes::new()))
                .expect("request"),
        )
        .await
        .expect("warmish restart");
    let metadata = restarted.body().metadata();
    assert!(metadata.worker_created);
    assert_eq!(metadata.package_tier, PackageTier::Warmish);
    restarted
        .into_body()
        .collect()
        .await
        .expect("restarted body");
    assert_eq!(service.metrics().workers_created, 2);
}
