//! Shared-cache, eviction, and multi-service HTTP stress coverage.

use runtrue_wasm_runtime::{
    AotAuthenticationKey, DiskCacheConfig, HttpRequest, HttpServiceConfig, PackageTier, Runtime,
    RuntimeConfig,
};
use std::{fs, sync::Arc, time::Duration};

const P2_HELLO: &[u8] = include_bytes!("fixtures/p2-http-hello.component.wasm");
const P3_HELLO: &[u8] = include_bytes!("fixtures/p3-http-hello.component.wasm");
const JSON_TOOL: &[u8] = include_bytes!("fixtures/json-http-tool.component.wasm");

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_preparation_publishes_one_shared_disk_artifact() {
    let directory = tempfile::TempDir::new().expect("cache directory");
    let runtime = Runtime::new(RuntimeConfig {
        disk_cache: Some(DiskCacheConfig::new(
            directory.path(),
            AotAuthenticationKey::new([22; 32]),
        )),
        background_workers: 4,
        ..RuntimeConfig::default()
    })
    .expect("runtime");
    let program = Arc::new(runtime.load_bytes(P3_HELLO).expect("component"));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let program = Arc::clone(&program);
        tasks.spawn(async move { program.prepare().await });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.expect("task").expect("prepare"), PackageTier::Warm);
    }
    let entries = fs::read_dir(directory.path())
        .expect("cache entries")
        .collect::<Result<Vec<_>, _>>()
        .expect("cache entry");
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.path().extension().is_some_and(|e| e == "aot"))
            .count(),
        1
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.path().extension().is_some_and(|e| e == "json"))
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_eviction_is_bounded_under_three_http_packages() {
    let runtime = Runtime::new(RuntimeConfig {
        max_warm_components: 1,
        max_warmish_entries: 2,
        max_warmish_bytes: 64 * 1024 * 1024,
        ..RuntimeConfig::default()
    })
    .expect("runtime");
    let programs = [P2_HELLO, P3_HELLO, JSON_TOOL]
        .into_iter()
        .map(|bytes| runtime.load_bytes(bytes).expect("component"))
        .collect::<Vec<_>>();
    for program in &programs {
        let service = program
            .http_service(HttpServiceConfig::default())
            .await
            .expect("prepare HTTP service");
        drop(service);
    }
    let tiers = programs
        .iter()
        .map(runtrue_wasm_runtime::Program::tier)
        .collect::<Vec<_>>();
    assert_eq!(
        tiers
            .iter()
            .filter(|tier| **tier == PackageTier::Warm)
            .count(),
        1
    );
    assert!(
        tiers
            .iter()
            .filter(|tier| **tier == PackageTier::Warmish)
            .count()
            <= 2
    );
    assert!(tiers.contains(&PackageTier::Cold));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_services_sustain_concurrent_requests_with_bounded_workers() {
    let runtime = Runtime::with_defaults().expect("runtime");
    let program = runtime.load_bytes(P3_HELLO).expect("component");
    let mut services = Vec::new();
    for _ in 0..8 {
        services.push(
            program
                .http_service(HttpServiceConfig {
                    max_in_flight: 8,
                    max_instance_concurrent_reuse_count: 8,
                    idle_worker_ttl: Duration::from_secs(5),
                    ..HttpServiceConfig::default()
                })
                .await
                .expect("service"),
        );
    }
    let mut tasks = tokio::task::JoinSet::new();
    for request_id in 0..256 {
        let service = services[request_id % services.len()].clone();
        tasks.spawn(async move {
            service
                .handle(HttpRequest::new("GET", "http://service.local/", Vec::new()))
                .await
        });
    }
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        let response = result.expect("task").expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"Hello, WASI!");
        completed += 1;
    }
    assert_eq!(completed, 256);
    for service in services {
        assert!(service.metrics().live_workers <= 8);
    }
}
