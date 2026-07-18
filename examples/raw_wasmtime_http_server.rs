//! Minimal raw Wasmtime embedding baseline for a WASI HTTP 0.2 component.

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use wasmtime::{
    Config, Engine, OptLevel, Store, StoreContextMut,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::{
    WasiHttpCtx,
    handler::{
        self, HandlerState, Instance, ProxyHandler, ProxyPre, ShouldAccept, ViewFn,
        WorkerExpiration, WorkerState, WorkerStatus,
    },
    io::TokioIo,
};

#[derive(Clone, Copy)]
struct DenyHooks;

impl wasmtime_wasi_http::p2::WasiHttpHooks for DenyHooks {}

struct Host {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    hooks: DenyHooks,
    table: ResourceTable,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl wasmtime_wasi_http::p2::WasiHttpView for Host {
    fn http(&mut self) -> wasmtime_wasi_http::p2::WasiHttpCtxView<'_> {
        wasmtime_wasi_http::p2::WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.hooks,
        }
    }
}

struct RawHandler {
    engine: Engine,
    pre: Arc<ProxyPre<Host>>,
}

impl HandlerState for RawHandler {
    type StoreData = Host;
    type WorkerExpiration = RequestExpiration;
    type WorkerState = ReusableWorker;

    async fn instantiate(
        &self,
    ) -> wasmtime::Result<Instance<Self::StoreData, Self::WorkerExpiration, Self::WorkerState>>
    {
        let mut wasi = WasiCtx::builder();
        wasi.allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false);
        let mut store = Store::new(
            &self.engine,
            Host {
                wasi: wasi.build(),
                http: WasiHttpCtx::new(),
                hooks: DenyHooks,
                table: ResourceTable::new(),
            },
        );
        store.set_fuel(10_000_000_000)?;
        store.set_epoch_deadline(u64::MAX / 2);
        let proxy = self.pre.instantiate_async(&mut store).await?;
        Ok(Instance {
            store,
            proxy,
            view: ViewFn::P2(wasmtime_wasi_http::p2::WasiHttpView::http),
            expiration: RequestExpiration(Box::pin(tokio::time::sleep(Duration::MAX))),
            state: ReusableWorker,
        })
    }
}

struct RequestExpiration(Pin<Box<tokio::time::Sleep>>);

impl WorkerExpiration for RequestExpiration {
    fn poll(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        status: WorkerStatus,
        start: Instant,
    ) -> Poll<()> {
        let timeout = match status {
            WorkerStatus::Idle => Duration::from_secs(1),
            WorkerStatus::Requests | WorkerStatus::PostReturn => Duration::from_secs(5),
        };
        let deadline = tokio::time::Instant::from_std(start + timeout);
        let sleep = &mut self.get_mut().0;
        if sleep.deadline() != deadline {
            sleep.as_mut().reset(deadline);
        }
        sleep.as_mut().poll(context)
    }
}

struct ReusableWorker;

impl WorkerState for ReusableWorker {
    type StoreData = Host;
    type RequestId = u64;

    fn should_accept_request(&self, concurrent: usize, total: usize) -> ShouldAccept {
        if total >= 10_000 {
            ShouldAccept::Never
        } else if concurrent == 0 {
            ShouldAccept::Yes
        } else {
            ShouldAccept::No
        }
    }

    fn on_request_start(
        &self,
        _store: StoreContextMut<'_, Host>,
        _id: u64,
        _task: wasmtime::component::GuestTaskId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>> {
        Box::pin(tokio::time::sleep(Duration::from_secs(5)))
    }

    fn drop(&self, store: Store<Host>, _result: wasmtime::Result<()>) {
        drop(store);
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let component_path = arguments.next().ok_or("missing component path")?;
    let address = arguments
        .next()
        .unwrap_or_else(|| "127.0.0.1:8081".to_owned());
    if arguments.next().is_some() {
        return Err("usage: raw_wasmtime_http_server <component.wasm> [address]".into());
    }
    let started = Instant::now();
    let mut config = Config::new();
    config
        .wasm_component_model(true)
        .wasm_component_model_async(true)
        .wasm_component_model_more_async_builtins(true)
        .wasm_component_model_async_stackful(true)
        .wasm_stack_switching(true)
        .consume_fuel(true)
        .epoch_interruption(true)
        .wasm_relaxed_simd(false)
        .wasm_simd(false)
        .memory_reservation(0)
        .memory_reservation_for_growth(0)
        .cranelift_opt_level(OptLevel::SpeedAndSize)
        .cranelift_nan_canonicalization(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, component_path)?;
    let mut linker = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;
    let pre = linker.instantiate_pre(&component)?;
    let pre = wasmtime_wasi_http::p2::bindings::ProxyPre::new(pre)?;
    let handler = ProxyHandler::new(RawHandler {
        engine,
        pre: Arc::new(ProxyPre::P2(pre)),
    });
    let listener = TcpListener::bind(&address).await?;
    println!(
        "listening=http://{} startup_us={}",
        listener.local_addr()?,
        started.elapsed().as_micros()
    );
    let next_request = Arc::new(AtomicU64::new(1));
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let handler = handler.clone();
        let next_request = Arc::clone(&next_request);
        tokio::spawn(async move {
            let connection = http1::Builder::new().keep_alive(true).serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| {
                    dispatch(handler.clone(), Arc::clone(&next_request), request)
                }),
            );
            if let Err(error) = connection.await {
                eprintln!("connection failed: {error}");
            }
        });
    }
}

async fn dispatch(
    handler: ProxyHandler<RawHandler>,
    next_request: Arc<AtomicU64>,
    request: Request<Incoming>,
) -> Result<Response<http_body_util::combinators::UnsyncBoxBody<Bytes, wasmtime::Error>>, Infallible>
{
    let request = request.map(|body| {
        body.map_err(
            wasmtime_wasi_http::p3::bindings::http::types::ErrorCode::from_hyper_request_error,
        )
        .map_err(handler::ErrorCode::from)
        .boxed_unsync()
    });
    match handler
        .handle(next_request.fetch_add(1, Ordering::Relaxed), request)
        .await
    {
        Ok(response) => Ok(response),
        Err(error) => {
            eprintln!("guest failed: {error}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    Full::new(Bytes::from_static(b"guest failed"))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .expect("static response"))
        }
    }
}
