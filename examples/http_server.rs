//! Minimal HTTP/1 host for a standard WASI HTTP component.

use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use runtrue_wasm_runtime::{Error, HttpService, HttpServiceConfig, Runtime, StreamingHttpBody};
use std::{sync::Arc, time::Instant};
use tokio::net::TcpListener;
use wasmtime_wasi_http::io::TokioIo;

const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/p3-http-hello.component.wasm");

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let component_path = arguments.next();
    let address = arguments
        .next()
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned());
    if arguments.next().is_some() {
        return Err("usage: http_server [component.wasm] [address]".into());
    }

    let started = Instant::now();
    let runtime = Runtime::with_defaults()?;
    let program = match component_path {
        Some(path) => runtime.load_file(path)?,
        None => runtime.load_bytes(FIXTURE)?,
    };
    let service = Arc::new(program.http_service(HttpServiceConfig::default()).await?);
    let listener = TcpListener::bind(&address).await?;
    println!(
        "listening=http://{} startup_from={:?} startup_us={}",
        listener.local_addr()?,
        service.startup_from(),
        started.elapsed().as_micros()
    );

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            let connection = http1::Builder::new().keep_alive(true).serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| handle(Arc::clone(&service), request)),
            );
            if let Err(error) = connection.await {
                eprintln!("connection failed: {error}");
            }
        });
    }
}

async fn handle(
    service: Arc<HttpService>,
    request: Request<Incoming>,
) -> Result<Response<StreamingHttpBody>, Error> {
    service.handle_streaming(request).await
}
