use runtrue_wasm_runtime::{CommandInput, HttpRequest, HttpServiceConfig, Runtime};
use std::{error::Error, sync::Arc};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

const HTTP_COMPONENT: &[u8] = include_bytes!("../p3-http-hello.component.wasm");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Exercise the command API shown in the README with a standard WASI 0.2
    // command component made entirely in this clean consumer.
    let runtime = Runtime::with_defaults()?;
    let command = runtime.load_bytes(command_component()?)?;
    let output = command.run(CommandInput::new(b"consumer".to_vec())).await?;
    assert_eq!(output.exit_code, 0);

    // Exercise the standard WASI HTTP API over a real loopback TCP connection.
    let service = Arc::new(
        runtime
            .load_bytes(HTTP_COMPONENT)?
            .http_service(HttpServiceConfig::default())
            .await?,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request_bytes = Vec::new();
        loop {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request_bytes.extend_from_slice(&buffer[..read]);
            if request_bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let response = service
            .handle(HttpRequest::new(
                "GET",
                "http://localhost/package-consumer-smoke",
                Vec::new(),
            ))
            .await?;
        let head = format!(
            "HTTP/1.1 {} OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            response.status,
            response.body.len()
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&response.body).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"GET /package-consumer-smoke HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    server.await??;
    Ok(())
}

fn command_component() -> Result<Vec<u8>, wat::Error> {
    wat::parse_str(
        r#"
        (component
          (type $run-func (func (result (result))))
          (type $run-interface (instance
            (export "run" (func (type $run-func)))))
          (core module $command
            (func (export "run") (result i32) i32.const 0))
          (core instance $command-instance (instantiate $command))
          (func $run (type $run-func)
            (canon lift (core func $command-instance "run")))
          (instance $run-instance
            (export "run" (func $run)))
          (export "wasi:cli/run@0.2.12"
            (instance $run-instance)))
        "#,
    )
}
