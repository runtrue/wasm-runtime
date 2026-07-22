#![no_main]

use libfuzzer_sys::fuzz_target;
use runtrue_wasm_runtime::{
    HttpRequest, HttpServiceConfig, HttpServiceState, OutboundHttpGrant, Program,
    Runtime as WasmRuntime,
};
use std::{sync::OnceLock, time::Duration};
use tokio::runtime::{Builder, Runtime as TokioRuntime};

const HTTP_COMPONENT: &[u8] = include_bytes!("../../tests/fixtures/p3-http-hello.component.wasm");

struct Harness {
    executor: TokioRuntime,
    program: Program,
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let executor = Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("Tokio fuzz executor");
        let runtime = WasmRuntime::with_defaults().expect("runtime fuzz harness");
        let program = runtime
            .load_bytes(HTTP_COMPONENT)
            .expect("standard HTTP fixture");
        executor
            .block_on(program.prepare())
            .expect("prepare standard HTTP fixture");
        Harness { executor, program }
    })
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn byte(&mut self) -> u8 {
        let byte = self.input.get(self.position).copied().unwrap_or_default();
        self.position = self.position.saturating_add(1);
        byte
    }

    fn bytes(&mut self, maximum: usize) -> &'a [u8] {
        let requested = usize::from(self.byte()).min(maximum);
        let start = self.position.min(self.input.len());
        let end = start.saturating_add(requested).min(self.input.len());
        let value = &self.input[start..end];
        self.position = end;
        value
    }

    fn text(&mut self, maximum: usize) -> String {
        String::from_utf8_lossy(self.bytes(maximum)).into_owned()
    }
}

fuzz_target!(|input: &[u8]| {
    let mut cursor = Cursor::new(input);
    let include_grant = cursor.byte() & 1 == 1;
    let scheme = cursor.text(16);
    let authority = cursor.text(128);
    let method_count = usize::from(cursor.byte() % 5);
    let methods = (0..method_count)
        .map(|_| cursor.text(32))
        .collect::<Vec<_>>();
    let request_limit = u64::from(cursor.byte()) * 256;
    let response_limit = u64::from(cursor.byte()) * 256;
    let allow_private = cursor.byte() & 1 == 1;

    let outbound_grants = include_grant
        .then(|| {
            OutboundHttpGrant::new(scheme, authority)
                .with_methods(&methods)
                .with_body_limits(request_limit, response_limit)
                .allow_private_network(allow_private)
        })
        .into_iter()
        .collect();

    let config = HttpServiceConfig {
        max_in_flight: usize::from(cursor.byte() % 4),
        max_instance_reuse_count: usize::from(cursor.byte() % 4),
        max_instance_concurrent_reuse_count: usize::from(cursor.byte() % 4),
        idle_worker_ttl: Duration::from_millis(u64::from(cursor.byte())),
        request_timeout: Duration::from_millis(u64::from(cursor.byte())),
        outbound_grants,
    };
    let reuse_limit = config.max_instance_reuse_count;
    let request = HttpRequest::new(
        cursor.text(32),
        cursor.text(128),
        cursor.bytes(8 * 1024).to_vec(),
    )
    .with_header(cursor.text(64), cursor.bytes(256).to_vec());

    let harness = harness();
    harness.executor.block_on(async {
        // Configuration and request parsing are both untrusted boundaries.
        // Either may reject this input, but neither may panic.
        if let Ok(service) = harness.program.http_service(config).await {
            let _ = service.handle(request).await;

            // ProxyHandler workers are Tokio tasks which intentionally remain
            // resident until their reuse or idle limit is reached. Exhaust the
            // tiny fuzzed reuse limit, then drive task cleanup before
            // libFuzzer performs its per-input leak check.
            for _ in 1..reuse_limit {
                if service.state() == HttpServiceState::NoResidentWorker {
                    break;
                }
                let _ = service
                    .handle(HttpRequest::new(
                        "POST",
                        "http://localhost/tools/call",
                        b"{}",
                    ))
                    .await;
            }
            tokio::time::timeout(Duration::from_secs(1), async {
                while service.state() != HttpServiceState::NoResidentWorker {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("single-use fuzz workers must stop");
        }
    });
});
