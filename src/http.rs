use crate::{
    Error, PackageTier, Program, Result, WasiProfile,
    runtime::{HostState, PreparedComponent, RuntimeInner},
};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited, combinators::UnsyncBoxBody};
use hyper::body::{Body, Frame, SizeHint};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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
    /// Exact outbound HTTP capabilities. Empty denies every destination.
    pub outbound_grants: Vec<OutboundHttpGrant>,
}

impl Default for HttpServiceConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 1_000,
            max_instance_reuse_count: 10_000,
            max_instance_concurrent_reuse_count: 32,
            idle_worker_ttl: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
            outbound_grants: Vec::new(),
        }
    }
}

/// An exact outbound HTTP origin capability granted to a guest service.
///
/// Grants match scheme, authority (host and optional port), and method.
/// Wildcards, redirects, inherited host networking, and implicit credentials
/// are intentionally unsupported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHttpGrant {
    scheme: String,
    authority: String,
    methods: Vec<String>,
    max_request_bytes: u64,
    max_response_bytes: u64,
    allow_private_network: bool,
}

impl OutboundHttpGrant {
    /// Construct a grant for one exact origin. Call [`Self::with_methods`] to
    /// explicitly select the permitted methods.
    #[must_use]
    pub fn new(scheme: impl Into<String>, authority: impl Into<String>) -> Self {
        Self {
            scheme: scheme.into().to_ascii_lowercase(),
            authority: authority.into().to_ascii_lowercase(),
            methods: Vec::new(),
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 4 * 1024 * 1024,
            allow_private_network: false,
        }
    }

    /// Replace the explicitly allowed methods.
    #[must_use]
    pub fn with_methods(mut self, methods: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.methods = methods
            .into_iter()
            .map(|method| method.as_ref().to_owned())
            .collect();
        self
    }

    /// Set maximum outbound request and response body sizes.
    #[must_use]
    pub const fn with_body_limits(
        mut self,
        max_request_bytes: u64,
        max_response_bytes: u64,
    ) -> Self {
        self.max_request_bytes = max_request_bytes;
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Permit private, loopback, link-local, or literal-IP destinations for
    /// this exact origin. Intended for explicitly trusted local services.
    #[must_use]
    pub const fn allow_private_network(mut self, allow: bool) -> Self {
        self.allow_private_network = allow;
        self
    }
}

#[derive(Clone)]
pub(crate) struct HttpHooks {
    grants: Arc<[OutboundHttpGrant]>,
}

impl HttpHooks {
    pub(crate) fn deny() -> Self {
        Self {
            grants: Arc::from([]),
        }
    }

    fn new(grants: Vec<OutboundHttpGrant>) -> Self {
        Self {
            grants: Arc::from(grants),
        }
    }

    fn grant_for<B>(&self, request: &http::Request<B>) -> Option<OutboundHttpGrant> {
        let scheme = request.uri().scheme_str()?;
        let authority = request.uri().authority()?.as_str();
        self.grants
            .iter()
            .find(|grant| {
                grant.scheme.eq_ignore_ascii_case(scheme)
                    && grant.authority.eq_ignore_ascii_case(authority)
                    && grant
                        .methods
                        .iter()
                        .any(|method| method.eq_ignore_ascii_case(request.method().as_str()))
                    && content_length_at_most(request.headers(), grant.max_request_bytes)
            })
            .cloned()
    }
}

impl wasmtime_wasi_http::p2::WasiHttpHooks for HttpHooks {
    fn send_request(
        &mut self,
        request: hyper::Request<wasmtime_wasi_http::p2::body::HyperOutgoingBody>,
        config: wasmtime_wasi_http::p2::types::OutgoingRequestConfig,
    ) -> wasmtime_wasi_http::p2::HttpResult<wasmtime_wasi_http::p2::types::HostFutureIncomingResponse>
    {
        use wasmtime_wasi_http::p2::{bindings::http::types::ErrorCode, types};

        let grant = self
            .grant_for(&request)
            .ok_or(ErrorCode::HttpRequestDenied)?;
        let handle = wasmtime_wasi::runtime::spawn(async move {
            Ok(async move {
                validate_network_destination(request.uri(), &grant)
                    .await
                    .map_err(|()| ErrorCode::DestinationIpProhibited)?;
                let (parts, body) = request.into_parts();
                let request = http::Request::from_parts(
                    parts,
                    LimitBody::new(body, grant.max_request_bytes, |_| {
                        ErrorCode::HttpRequestBodySize(None)
                    })
                    .boxed_unsync(),
                );
                let mut incoming =
                    wasmtime_wasi_http::p2::default_send_request_handler(request, config).await?;
                if !content_length_at_most(incoming.resp.headers(), grant.max_response_bytes) {
                    return Err(ErrorCode::HttpResponseBodySize(None));
                }
                incoming.resp = incoming.resp.map(|body| {
                    LimitBody::new(body, grant.max_response_bytes, |_| {
                        ErrorCode::HttpResponseBodySize(None)
                    })
                    .boxed_unsync()
                });
                Ok::<types::IncomingResponse, ErrorCode>(incoming)
            }
            .await)
        });
        Ok(types::HostFutureIncomingResponse::pending(handle))
    }
}

impl wasmtime_wasi_http::p3::WasiHttpHooks for HttpHooks {
    fn send_request(
        &mut self,
        request: http::Request<
            http_body_util::combinators::UnsyncBoxBody<
                Bytes,
                wasmtime_wasi_http::p3::bindings::http::types::ErrorCode,
            >,
        >,
        options: Option<wasmtime_wasi_http::p3::RequestOptions>,
        fut: Box<
            dyn Future<
                    Output = std::result::Result<
                        (),
                        wasmtime_wasi_http::p3::bindings::http::types::ErrorCode,
                    >,
                > + Send,
        >,
    ) -> Box<
        dyn Future<
                Output = std::result::Result<
                    (
                        http::Response<
                            http_body_util::combinators::UnsyncBoxBody<
                                Bytes,
                                wasmtime_wasi_http::p3::bindings::http::types::ErrorCode,
                            >,
                        >,
                        Box<
                            dyn Future<
                                    Output = std::result::Result<
                                        (),
                                        wasmtime_wasi_http::p3::bindings::http::types::ErrorCode,
                                    >,
                                > + Send,
                        >,
                    ),
                    wasmtime_wasi::TrappableError<
                        wasmtime_wasi_http::p3::bindings::http::types::ErrorCode,
                    >,
                >,
            > + Send,
    > {
        use wasmtime_wasi_http::p3::bindings::http::types::ErrorCode;

        let Some(grant) = self.grant_for(&request) else {
            return Box::new(async { Err(ErrorCode::HttpRequestDenied.into()) });
        };
        Box::new(async move {
            validate_network_destination(request.uri(), &grant)
                .await
                .map_err(|()| ErrorCode::DestinationIpProhibited)?;
            let (parts, body) = request.into_parts();
            let request = http::Request::from_parts(
                parts,
                LimitBody::new(body, grant.max_request_bytes, |_| {
                    ErrorCode::HttpRequestBodySize(None)
                })
                .boxed_unsync(),
            );
            let (response, io) = wasmtime_wasi_http::p3::default_send_request(request, options)
                .await
                .map_err(wasmtime_wasi::TrappableError::from)?;
            if !content_length_at_most(response.headers(), grant.max_response_bytes) {
                return Err(ErrorCode::HttpResponseBodySize(None).into());
            }
            Ok((
                response.map(|body| {
                    LimitBody::new(body, grant.max_response_bytes, |_| {
                        ErrorCode::HttpResponseBodySize(None)
                    })
                    .boxed_unsync()
                }),
                Box::new(async move {
                    let request_result = Box::into_pin(fut).await;
                    let response_result = io.await;
                    request_result.and(response_result)
                })
                    as Box<dyn Future<Output = std::result::Result<(), ErrorCode>> + Send>,
            ))
        })
    }
}

fn content_length_at_most(headers: &http::HeaderMap, limit: u64) -> bool {
    headers
        .get(http::header::CONTENT_LENGTH)
        .map_or(Some(0), |value| value.to_str().ok()?.parse::<u64>().ok())
        .is_some_and(|length| length <= limit)
}

async fn validate_network_destination(
    uri: &http::Uri,
    grant: &OutboundHttpGrant,
) -> std::result::Result<(), ()> {
    if grant.allow_private_network {
        return Ok(());
    }
    let authority = uri.authority().ok_or(())?;
    let port = authority
        .port_u16()
        .unwrap_or(if grant.scheme == "https" { 443 } else { 80 });
    let addresses = tokio::net::lookup_host((authority.host(), port))
        .await
        .map_err(|_| ())?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(());
    }
    Ok(())
}

fn is_public_ip(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !(a == 0
                || address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_unspecified()
                || address.is_multicast()
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && matches!(b, 18 | 19))
                || a >= 240)
        }
        std::net::IpAddr::V6(address) => {
            let segments = address.segments();
            (segments[0] & 0xe000) == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_public_ip;

    #[test]
    fn public_address_filter_fails_closed_for_special_ranges() {
        for address in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.0.1",
            "192.88.99.1",
            "198.18.0.1",
            "203.0.113.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !is_public_ip(address.parse().expect("IP address")),
                "{address}"
            );
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}

struct LimitBody<B, E> {
    body: Pin<Box<B>>,
    remaining: u64,
    error: fn(u64) -> E,
}

impl<B, E> LimitBody<B, E> {
    fn new(body: B, limit: u64, error: fn(u64) -> E) -> Self {
        Self {
            body: Box::pin(body),
            remaining: limit,
            error,
        }
    }
}

impl<B, E> hyper::body::Body for LimitBody<B, E>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<E>,
    E: 'static,
{
    type Data = Bytes;
    type Error = E;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, E>>> {
        let me = self.get_mut();
        let frame = ready!(me.body.as_mut().poll_frame(cx));
        match frame {
            Some(Ok(frame)) => {
                let bytes = frame.data_ref().map_or(0, Bytes::len) as u64;
                if bytes > me.remaining {
                    me.remaining = 0;
                    Poll::Ready(Some(Err((me.error)(bytes))))
                } else {
                    me.remaining -= bytes;
                    Poll::Ready(Some(Ok(frame)))
                }
            }
            Some(Err(error)) => Poll::Ready(Some(Err(error.into()))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut hint = self.body.size_hint();
        if hint.upper().is_none_or(|upper| upper > self.remaining) {
            hint.set_upper(self.remaining);
        }
        hint
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
#[non_exhaustive]
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

/// Allocation-free per-request telemetry for the streaming HTTP path.
///
/// A control plane can read this from [`StreamingHttpBody::metadata`] before
/// handing the response body to its network server. Request identifiers are
/// monotonically increasing and unique within one [`HttpService`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct HttpDispatchMetadata {
    /// Service-local request identifier passed to the WASI HTTP handler.
    pub request_id: u64,
    /// Package tier observed when the request entered the service.
    pub package_tier: PackageTier,
    /// Whether at least one new worker was created while producing headers.
    pub worker_created: bool,
    /// Time from entering the service until response headers were available.
    pub headers_elapsed: Duration,
}

/// Streaming response body returned by [`HttpService::handle_streaming`].
///
/// The body keeps its service admission permit until it is fully consumed or
/// dropped. Response bytes are bounded by the runtime output limit without
/// buffering or reconstructing the response.
pub struct StreamingHttpBody {
    inner: UnsyncBoxBody<Bytes, wasmtime::Error>,
    remaining: usize,
    completion: Option<HttpRequestCompletion>,
    metadata: HttpDispatchMetadata,
}

impl std::fmt::Debug for StreamingHttpBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamingHttpBody")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl StreamingHttpBody {
    /// Per-request tier, worker, identifier, and header timing telemetry.
    #[must_use]
    pub const fn metadata(&self) -> HttpDispatchMetadata {
        self.metadata
    }
}

impl Body for StreamingHttpBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let body = self.get_mut();
        match Pin::new(&mut body.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if data.len() > body.remaining {
                        body.remaining = 0;
                        body.completion.take();
                        return Poll::Ready(Some(Err(Error::Limit("output bytes"))));
                    }
                    body.remaining -= data.len();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                body.completion.take();
                Poll::Ready(Some(Err(Error::Execution(error.to_string()))))
            }
            Poll::Ready(None) => {
                if let Some(completion) = body.completion.take() {
                    completion.complete();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Observable residency state for an HTTP service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
    package_tier: Arc<AtomicUsize>,
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
        let package_tier = Arc::new(AtomicUsize::new(package_tier_code(PackageTier::Warm)));
        let state = HttpHandlerState {
            runtime: Arc::clone(&self.runtime.inner),
            digest: self.digest.clone(),
            bytes: Arc::clone(&self.bytes),
            pre: Arc::clone(&pre_slot),
            profile: prepared.profile,
            config: config.clone(),
            metrics: Arc::clone(&metrics),
            package_tier: Arc::clone(&package_tier),
            next_request: AtomicU64::new(1),
        };
        Ok(HttpService {
            handler: ProxyHandler::new(state),
            admission: Arc::new(Semaphore::new(config.max_in_flight)),
            metrics,
            package_tier,
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
        package_tier_from_code(self.package_tier.load(Ordering::Relaxed))
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
        let workers_before = self.metrics.workers_created.load(Ordering::Relaxed);
        self.metrics.in_flight.fetch_add(1, Ordering::Relaxed);
        let completion = HttpRequestCompletion {
            metrics: Arc::clone(&self.metrics),
            _permit: permit,
        };
        let request = build_request(request)?;
        let id = self
            .handler
            .state()
            .next_request
            .fetch_add(1, Ordering::Relaxed);
        let response = self.handler.handle(id, request).await;
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
        completion.complete();
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
            worker_created: self.metrics.workers_created.load(Ordering::Relaxed) > workers_before,
        })
    }

    /// Dispatch a standard HTTP request without buffering or reconstructing
    /// its body, headers, URI, or response.
    ///
    /// This is the low-overhead host integration path. It preserves admission,
    /// guest timeouts, worker reuse, capability enforcement, metrics, and
    /// request/response byte limits. The returned body must be consumed or
    /// dropped to release its admission permit.
    ///
    /// # Errors
    ///
    /// Returns an error for admission shutdown, guest instantiation, traps, or
    /// failure to produce response headers. Streaming body failures are
    /// reported by [`StreamingHttpBody`].
    pub async fn handle_streaming<B>(
        &self,
        request: http::Request<B>,
    ) -> Result<http::Response<StreamingHttpBody>>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let started = Instant::now();
        let package_tier = self.package_tier();
        let max_input_bytes = self.handler.state().runtime.config.limits.max_input_bytes;
        let max_input_u64 = u64::try_from(max_input_bytes).unwrap_or(u64::MAX);
        let size_hint = request.body().size_hint();
        if size_hint.lower() > max_input_u64
            || size_hint.upper().is_some_and(|upper| upper > max_input_u64)
        {
            return Err(Error::Limit("input bytes"));
        }
        let request = request.map(|body| {
            Limited::new(body, max_input_bytes)
                .map_err(streaming_request_error)
                .boxed_unsync()
        });
        let permit = Arc::clone(&self.admission)
            .acquire_owned()
            .await
            .map_err(|_| Error::InvalidState("HTTP service is closed"))?;
        self.metrics.in_flight.fetch_add(1, Ordering::Relaxed);
        let completion = HttpRequestCompletion {
            metrics: Arc::clone(&self.metrics),
            _permit: permit,
        };
        let workers_before = self.metrics.workers_created.load(Ordering::Relaxed);
        let id = self
            .handler
            .state()
            .next_request
            .fetch_add(1, Ordering::Relaxed);
        let response = match self.handler.handle(id, request).await {
            Ok(response) => response,
            Err(error) => {
                drop(completion);
                return Err(Error::Execution(error.to_string()));
            }
        };
        let metadata = HttpDispatchMetadata {
            request_id: id,
            package_tier,
            worker_created: self.metrics.workers_created.load(Ordering::Relaxed) > workers_before,
            headers_elapsed: started.elapsed(),
        };
        let max_output_bytes = self.handler.state().runtime.config.limits.max_output_bytes;
        Ok(response.map(|body| {
            let mut completion = Some(completion);
            if body.is_end_stream()
                && let Some(completion) = completion.take()
            {
                completion.complete();
            }
            StreamingHttpBody {
                inner: body,
                remaining: max_output_bytes,
                completion,
                metadata,
            }
        }))
    }
}

fn streaming_request_error(error: Box<dyn std::error::Error + Send + Sync>) -> handler::ErrorCode {
    use wasmtime_wasi_http::p3::bindings::http::types::ErrorCode;

    let error = match error.downcast::<http_body_util::LengthLimitError>() {
        Ok(_) => ErrorCode::HttpRequestBodySize(None),
        Err(error) => ErrorCode::InternalError(Some(error.to_string())),
    };
    error.into()
}

struct HttpRequestCompletion {
    metrics: Arc<HttpMetrics>,
    _permit: OwnedSemaphorePermit,
}

impl HttpRequestCompletion {
    fn complete(self) {
        self.metrics
            .completed_requests
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for HttpRequestCompletion {
    fn drop(&mut self) {
        self.metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

const fn package_tier_code(tier: PackageTier) -> usize {
    match tier {
        PackageTier::Cold => 0,
        PackageTier::DiskAot => 1,
        PackageTier::Warmish => 2,
        PackageTier::Warm => 3,
    }
}

const fn package_tier_from_code(code: usize) -> PackageTier {
    match code {
        0 => PackageTier::Cold,
        1 => PackageTier::DiskAot,
        2 => PackageTier::Warmish,
        _ => PackageTier::Warm,
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
        WasiProfile::Http0_3 => runtime.p3_linker()?.instantiate_pre(&prepared.component),
        WasiProfile::Http0_2 => runtime.p2_linker()?.instantiate_pre(&prepared.component),
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
    package_tier: Arc<AtomicUsize>,
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
                http_hooks: HttpHooks::new(self.config.outbound_grants.clone()),
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
        self.package_tier
            .store(package_tier_code(PackageTier::Warm), Ordering::Relaxed);
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
                package_tier: Arc::clone(&self.package_tier),
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
    package_tier: Arc<AtomicUsize>,
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
            self.package_tier
                .store(package_tier_code(PackageTier::Warmish), Ordering::Relaxed);
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
    for grant in &config.outbound_grants {
        if !matches!(grant.scheme.as_str(), "http" | "https") {
            return Err(Error::Configuration(
                "outbound HTTP grant scheme must be http or https".to_owned(),
            ));
        }
        if grant.authority.is_empty()
            || grant.authority.contains('@')
            || grant.methods.is_empty()
            || grant
                .methods
                .iter()
                .any(|method| http::Method::from_bytes(method.as_bytes()).is_err())
            || grant.max_request_bytes == 0
            || grant.max_response_bytes == 0
        {
            return Err(Error::Configuration(
                "outbound HTTP grants require an authority, at least one method, and positive body limits"
                    .to_owned(),
            ));
        }
        http::Uri::builder()
            .scheme(grant.scheme.as_str())
            .authority(grant.authority.as_str())
            .path_and_query("/")
            .build()
            .map_err(|error| {
                Error::Configuration(format!("invalid outbound HTTP origin: {error}"))
            })?;
    }
    Ok(())
}
