//! Minimal HTTP/1 host for a standard WASI HTTP component.

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use runtrue_wasm_runtime::{HttpRequest, HttpService, HttpServiceConfig, Runtime};
use std::{convert::Infallible, sync::Arc, time::Instant};
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
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let body = match http_body_util::Limited::new(body, 1024 * 1024)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return Ok(response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
    };
    let mut guest = HttpRequest::new(parts.method.as_str(), parts.uri.to_string(), body.to_vec());
    guest.headers = parts
        .headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    match service.handle(guest).await {
        Ok(output) => {
            let mut builder = Response::builder().status(output.status);
            for (name, value) in output.headers {
                builder = builder.header(name, value);
            }
            Ok(builder
                .body(Full::new(Bytes::from(output.body)))
                .unwrap_or_else(|_| {
                    response(StatusCode::INTERNAL_SERVER_ERROR, "invalid response")
                }))
        }
        Err(error) => Ok(response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("guest failed: {error}"),
        )),
    }
}

fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("static response is valid")
}
