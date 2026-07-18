use crate::{
    Error, PackageTier, Program, Result, WasiProfile,
    runtime::{DenyHttpHooks, HostState, PreparedComponent, RuntimeInner},
};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use wasmtime::{Store, StoreContextMut, StoreLimitsBuilder, component::GuestTaskId};
use wasmtime_wasi_http::handler::{
    self, HandlerState, Instance, ProxyHandler, ProxyPre, ShouldAccept, ViewFn, WorkerExpiration,
    WorkerState, WorkerStatus,
};

/// Bounded configuration for a reusable standard WASI HTTP service.
#[derive(Debug, Clone)]
pub struct HttpServiceConfig {
    /// Maximum requests admitted into the handler at once.
    pub max_in_flight: usize,
    /// Maximum total requests handled by one guest instance.
    pub max_instance_reuse_count: usize,
    /// Maximum concurrent requests handled by one WASI 0.3 guest instance.
    /// WASI 0.2 instances are always limited to one.
    pub max_instance_concurrent_reuse_count: usize,
    /// Time an idle live instance remains resident for a fast resumed request.
    pub idle_worker_ttl: Duration,
    /// Maximum time for the guest to produce each response.
    pub request_timeout: Duration,
}

impl Default for HttpServiceConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 1_000,
            max_instance_reuse_count: 10_000,
            max_instance_concurrent_reuse_count: 32,
            idle_worker_ttl: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Complete buffered request dispatched to a standard WASI HTTP handler.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: String,
    /// Absolute or origin-form request URI.
    pub uri: String,
    /// Header name/value pairs. Duplicate names are preserved.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Buffered request body.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Construct a request with no headers.
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        uri: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Append a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Buffered response returned by a standard WASI HTTP handler.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Header name/value pairs. Duplicate names are preserved.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Buffered response body.
    pub body: Vec<u8>,
    /// End-to-end handler time, including admission and worker creation.
    pub elapsed: Duration,
    /// Package tier observed when the request entered the service.
    pub package_tier: PackageTier,
    /// Whether at least one new worker was created while this request ran.
    pub worker_created: bool,
}

/// Observable residency state for an HTTP service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpServiceState {
    /// No live guest instance is retained; the next request creates one.
    NoResidentWorker,
    /// One or more requests are executing.
    Active,
    /// A live reusable guest instance is idle and waiting for a request.
    PausedResident,
}

/// Point-in-time HTTP worker counters.
#[derive(Debug, Clone, Copy)]
pub struct HttpServiceMetrics {
    /// Workers created since service construction.
    pub workers_created: u64,
    /// Workers currently retaining a Store and component instance.
    pub live_workers: usize,
    /// Workers dropped because their idle TTL expired.
    pub idle_evictions: u64,
    /// Requests currently admitted.
    pub in_flight: usize,
    /// Successfully returned responses.
    pub completed_requests: u64,
}

/// A reusable standard WASI HTTP handler with bounded admission and idle eviction.
#[derive(Clone)]
pub struct HttpService {
    handler: ProxyHandler<HttpHandlerState>,
    admission: Arc<Semaphore>,
    metrics: Arc<HttpMetrics>,
    program: Program,
    profile: WasiProfile,
    startup_from: PackageTier,
    startup_prepare: Duration,
    startup_total: Duration,
}

impl std::fmt::Debug for HttpService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpService")
            .field("profile", &self.profile)
            .field("state", &self.state())
            .field("metrics", &self.metrics())
            .finish_non_exhaustive()
    }
}

impl Program {
    /// Prepare this component as a standard WASI HTTP service.
    ///
    /// The returned service automatically retains idle workers as the fastest
    /// tier and evicts them after `idle_worker_ttl`, demoting package code to
    /// warmish so later requests can restart without recompilation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid service limits, a non-HTTP component, or
    /// failed preparation/pre-instantiation.
    pub async fn http_service(&self, config: HttpServiceConfig) -> Result<HttpService> {
        validate_config(&config, self.runtime.inner.config.limits.max_timeout)?;
        let total_started = Instant::now();
        let startup_from = self.tier();
        let prepare_started = Instant::now();
        let prepared = self
            .runtime
            .inner
            .prepare(&self.digest, Arc::clone(&self.bytes))
            .await?;
        let startup_prepare = prepare_started.elapsed();
        if !prepared.profile.is_http() {
            return Err(Error::UnsupportedComponent(
                "expected wasi:http/handler@0.3.x or incoming-handler@0.2.x".to_owned(),
            ));
        }

        let pre = make_proxy_pre(&self.runtime.inner, &prepared)?;
        let metrics = Arc::new(HttpMetrics::default());
        let pre_slot = Arc::new(Mutex::new(Some(Arc::new(pre))));
        let state = HttpHandlerState {
            runtime: Arc::clone(&self.runtime.inner),
            digest: self.digest.clone(),
            bytes: Arc::clone(&self.bytes),
            pre: Arc::clone(&pre_slot),
            profile: prepared.profile,
            config: config.clone(),
            metrics: Arc::clone(&metrics),
            next_request: AtomicU64::new(1),
        };
        Ok(HttpService {
            handler: ProxyHandler::new(state),
            admission: Arc::new(Semaphore::new(config.max_in_flight)),
            metrics,
            program: self.clone(),
            profile: prepared.profile,
            startup_from,
            startup_prepare,
            startup_total: total_started.elapsed(),
        })
    }
}

impl HttpService {
    /// Standard WASI HTTP profile selected for this component.
    #[must_use]
    pub const fn profile(&self) -> WasiProfile {
        self.profile
    }

    /// Package tier observed before service preparation began.
    #[must_use]
    pub const fn startup_from(&self) -> PackageTier {
        self.startup_from
    }

    /// Time spent preparing code while the service was constructed.
    #[must_use]
    pub const fn startup_prepare(&self) -> Duration {
        self.startup_prepare
    }

    /// Total time spent constructing the service, including pre-instantiation.
    #[must_use]
    pub const fn startup_total(&self) -> Duration {
        self.startup_total
    }

    /// Current package code tier.
    #[must_use]
    pub fn package_tier(&self) -> PackageTier {
        self.program.tier()
    }

    /// Current worker residency state.
    #[must_use]
    pub fn state(&self) -> HttpServiceState {
        let in_flight = self.metrics.in_flight.load(Ordering::Acquire);
        if in_flight > 0 {
            HttpServiceState::Active
        } else if self.metrics.live_workers.load(Ordering::Acquire) > 0 {
            HttpServiceState::PausedResident
        } else {
            HttpServiceState::NoResidentWorker
        }
    }

    /// Current service counters.
    #[must_use]
    pub fn metrics(&self) -> HttpServiceMetrics {
        HttpServiceMetrics {
            workers_created: self.metrics.workers_created.load(Ordering::Acquire),
            live_workers: self.metrics.live_workers.load(Ordering::Acquire),
            idle_evictions: self.metrics.idle_evictions.load(Ordering::Acquire),
            in_flight: self.metrics.in_flight.load(Ordering::Acquire),
            completed_requests: self.metrics.completed_requests.load(Ordering::Acquire),
        }
    }

    /// Dispatch one buffered request to the standard guest handler.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed HTTP input, admission shutdown, guest
    /// instantiation/trap/timeout, or response-size limit violations.
    pub async fn handle(&self, request: HttpRequest) -> Result<HttpResponse> {
        if request.body.len() > self.handler.state().runtime.config.limits.max_input_bytes {
            return Err(Error::Limit("input bytes"));
        }
        let permit = Arc::clone(&self.admission)
            .acquire_owned()
            .await
            .map_err(|_| Error::InvalidState("HTTP service is closed"))?;
        let started = Instant::now();
        let tier = self.package_tier();
        let workers_before = self.metrics.workers_created.load(Ordering::Acquire);
        self.metrics.in_flight.fetch_add(1, Ordering::AcqRel);
        let request = build_request(request)?;
        let id = self
            .handler
            .state()
            .next_request
            .fetch_add(1, Ordering::Relaxed);
        let response = self.handler.handle(id, request).await;
        self.metrics.in_flight.fetch_sub(1, Ordering::AcqRel);
        drop(permit);
        let response = response.map_err(|error| Error::Execution(error.to_string()))?;
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|error| Error::Execution(error.to_string()))?
            .to_bytes();
        if body.len() > self.handler.state().runtime.config.limits.max_output_bytes {
            return Err(Error::Limit("output bytes"));
        }
        self.metrics
            .completed_requests
            .fetch_add(1, Ordering::AcqRel);
        Ok(HttpResponse {
            status: parts.status.as_u16(),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
                .collect(),
            body: body.to_vec(),
            elapsed: started.elapsed(),
            package_tier: tier,
            worker_created: self.metrics.workers_created.load(Ordering::Acquire) > workers_before,
        })
    }
}

fn build_request(request: HttpRequest) -> Result<handler::Request> {
    let mut builder = http::Request::builder()
        .method(request.method.as_str())
        .uri(request.uri.as_str());
    for (name, value) in request.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(
            Full::new(Bytes::from(request.body))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .map_err(|error| Error::Execution(format!("invalid HTTP request: {error}")))
}

fn make_proxy_pre(
    runtime: &RuntimeInner,
    prepared: &PreparedComponent,
) -> Result<ProxyPre<HostState>> {
    let instance = match prepared.profile {
        WasiProfile::Http0_3 => runtime.p3_linker.instantiate_pre(&prepared.component),
        WasiProfile::Http0_2 => runtime.p2_linker.instantiate_pre(&prepared.component),
        WasiProfile::Cli0_3 | WasiProfile::Cli0_2 => unreachable!("validated above"),
    }
    .map_err(|error| Error::Preparation(error.to_string()))?;
    match prepared.profile {
        WasiProfile::Http0_3 => wasmtime_wasi_http::p3::bindings::ServicePre::new(instance)
            .map(ProxyPre::P3)
            .map_err(|error| Error::Preparation(error.to_string())),
        WasiProfile::Http0_2 => wasmtime_wasi_http::p2::bindings::ProxyPre::new(instance)
            .map(ProxyPre::P2)
            .map_err(|error| Error::Preparation(error.to_string())),
        WasiProfile::Cli0_3 | WasiProfile::Cli0_2 => unreachable!("validated above"),
    }
}

#[derive(Default)]
struct HttpMetrics {
    workers_created: AtomicU64,
    live_workers: AtomicUsize,
    idle_evictions: AtomicU64,
    in_flight: AtomicUsize,
    completed_requests: AtomicU64,
}

struct HttpHandlerState {
    runtime: Arc<RuntimeInner>,
    digest: String,
    bytes: Arc<[u8]>,
    pre: Arc<Mutex<Option<Arc<ProxyPre<HostState>>>>>,
    profile: WasiProfile,
    config: HttpServiceConfig,
    metrics: Arc<HttpMetrics>,
    next_request: AtomicU64,
}

impl HandlerState for HttpHandlerState {
    type StoreData = HostState;
    type WorkerExpiration = HttpWorkerExpiration;
    type WorkerState = HttpWorkerState;

    async fn instantiate(
        &self,
    ) -> wasmtime::Result<Instance<Self::StoreData, Self::WorkerExpiration, Self::WorkerState>>
    {
        let existing_pre = self.pre.lock().expect("HTTP pre lock poisoned").clone();
        let pre = if let Some(pre) = existing_pre {
            pre
        } else {
            let prepared = self
                .runtime
                .prepare(&self.digest, Arc::clone(&self.bytes))
                .await
                .map_err(|error| wasmtime::format_err!(error.to_string()))?;
            let candidate = Arc::new(
                make_proxy_pre(&self.runtime, &prepared)
                    .map_err(|error| wasmtime::format_err!(error.to_string()))?,
            );
            let mut slot = self.pre.lock().expect("HTTP pre lock poisoned");
            Arc::clone(slot.get_or_insert(candidate))
        };
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.runtime.config.limits.max_memory_bytes)
            .table_elements(self.runtime.config.limits.max_table_elements)
            .instances(self.runtime.config.limits.max_instances)
            .tables(100)
            .memories(100)
            .trap_on_grow_failure(true)
            .build();
        let mut wasi = wasmtime_wasi::WasiCtx::builder();
        wasi.allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false);
        let mut store = Store::new(
            &self.runtime.engine,
            HostState {
                wasi: wasi.build(),
                http: wasmtime_wasi_http::WasiHttpCtx::new(),
                http_hooks: DenyHttpHooks,
                table: wasmtime::component::ResourceTable::new(),
                limits,
            },
        );
        store.limiter(|state| &mut state.limits);
        store.set_fuel(self.runtime.config.limits.fuel)?;
        // ProxyHandler enforces request and idle deadlines outside the guest
        // event loop. Keep the shared epoch ticker from interrupting this
        // Store independently.
        store.set_epoch_deadline(u64::MAX / 2);
        let proxy = pre.instantiate_async(&mut store).await?;
        self.metrics.workers_created.fetch_add(1, Ordering::AcqRel);
        self.metrics.live_workers.fetch_add(1, Ordering::AcqRel);
        let idle_expired = Arc::new(AtomicBool::new(false));
        Ok(Instance {
            store,
            proxy,
            view: match self.profile {
                WasiProfile::Http0_3 => ViewFn::P3(wasmtime_wasi_http::p3::WasiHttpView::http),
                WasiProfile::Http0_2 => ViewFn::P2(wasmtime_wasi_http::p2::WasiHttpView::http),
                WasiProfile::Cli0_3 | WasiProfile::Cli0_2 => unreachable!(),
            },
            expiration: HttpWorkerExpiration {
                idle_timeout: self.config.idle_worker_ttl,
                request_timeout: self.config.request_timeout,
                sleep: Box::pin(tokio::time::sleep(Duration::MAX)),
                idle_expired: Arc::clone(&idle_expired),
            },
            state: HttpWorkerState {
                max_reuse: self.config.max_instance_reuse_count,
                max_concurrent: if self.profile == WasiProfile::Http0_3 {
                    self.config.max_instance_concurrent_reuse_count
                } else {
                    1
                },
                request_timeout: self.config.request_timeout,
                idle_expired,
                metrics: Arc::clone(&self.metrics),
                runtime: Arc::clone(&self.runtime),
                digest: self.digest.clone(),
                pre: Arc::clone(&self.pre),
            },
        })
    }
}

struct HttpWorkerExpiration {
    idle_timeout: Duration,
    request_timeout: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
    idle_expired: Arc<AtomicBool>,
}

impl WorkerExpiration for HttpWorkerExpiration {
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        status: WorkerStatus,
        start: Instant,
    ) -> Poll<()> {
        let me = self.get_mut();
        let timeout = match status {
            WorkerStatus::Idle => me.idle_timeout,
            WorkerStatus::Requests | WorkerStatus::PostReturn => me.request_timeout,
        };
        let Some(deadline) = start.checked_add(timeout) else {
            return Poll::Pending;
        };
        let deadline = tokio::time::Instant::from_std(deadline);
        if deadline != me.sleep.deadline() {
            me.sleep.as_mut().reset(deadline);
        }
        match me.sleep.as_mut().poll(cx) {
            Poll::Ready(()) => {
                if status == WorkerStatus::Idle {
                    me.idle_expired.store(true, Ordering::Release);
                }
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

struct HttpWorkerState {
    max_reuse: usize,
    max_concurrent: usize,
    request_timeout: Duration,
    idle_expired: Arc<AtomicBool>,
    metrics: Arc<HttpMetrics>,
    runtime: Arc<RuntimeInner>,
    digest: String,
    pre: Arc<Mutex<Option<Arc<ProxyPre<HostState>>>>>,
}

impl WorkerState for HttpWorkerState {
    type StoreData = HostState;
    type RequestId = u64;

    fn should_accept_request(&self, concurrent_count: usize, total_count: usize) -> ShouldAccept {
        if total_count >= self.max_reuse {
            ShouldAccept::Never
        } else if concurrent_count >= self.max_concurrent {
            ShouldAccept::No
        } else {
            ShouldAccept::Yes
        }
    }

    fn on_request_start(
        &self,
        _store: StoreContextMut<'_, HostState>,
        _id: u64,
        _task: GuestTaskId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>> {
        Box::pin(tokio::time::sleep(self.request_timeout))
    }

    fn drop(&self, store: Store<HostState>, _result: wasmtime::Result<()>) {
        drop(store);
        let previous_live = self.metrics.live_workers.fetch_sub(1, Ordering::AcqRel);
        if previous_live == 1 && self.idle_expired.load(Ordering::Acquire) {
            self.metrics.idle_evictions.fetch_add(1, Ordering::AcqRel);
            *self.pre.lock().expect("HTTP pre lock poisoned") = None;
            self.runtime.demote(&self.digest);
        }
    }
}

fn validate_config(config: &HttpServiceConfig, runtime_max_timeout: Duration) -> Result<()> {
    if config.max_in_flight == 0
        || config.max_instance_reuse_count == 0
        || config.max_instance_concurrent_reuse_count == 0
        || config.idle_worker_ttl.is_zero()
        || config.request_timeout.is_zero()
    {
        return Err(Error::Configuration(
            "HTTP capacities, idle TTL, and request timeout must be positive".to_owned(),
        ));
    }
    if config.request_timeout > runtime_max_timeout {
        return Err(Error::Limit("timeout"));
    }
    Ok(())
}
