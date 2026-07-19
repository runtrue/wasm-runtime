//! Outbound capability and request-timeout integration tests.

use runtrue_wasm_runtime::{HttpRequest, HttpServiceConfig, OutboundHttpGrant, Runtime};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PROXY_COMPONENT: &[u8] = include_bytes!("fixtures/p3-http-proxy.component.wasm");
const SLEEP_COMPONENT: &[u8] = include_bytes!("fixtures/p3-http-sleep.component.wasm");
const JSON_TOOL_COMPONENT: &[u8] = include_bytes!("fixtures/json-http-tool.component.wasm");

#[tokio::test]
async fn malformed_outbound_grants_fail_service_configuration() {
    let runtime = Runtime::with_defaults().expect("runtime");
    let program = runtime
        .load_bytes(PROXY_COMPONENT)
        .expect("proxy component");
    let result = program
        .http_service(HttpServiceConfig {
            outbound_grants: vec![OutboundHttpGrant::new("http", "example.com")],
            ..HttpServiceConfig::default()
        })
        .await;
    let Err(error) = result else {
        panic!("methodless grant must fail");
    };
    assert!(error.to_string().contains("outbound HTTP grants"));
}

#[tokio::test]
async fn outbound_http_is_denied_without_an_exact_grant() {
    let runtime = Runtime::with_defaults().expect("runtime");
    let service = runtime
        .load_bytes(PROXY_COMPONENT)
        .expect("proxy component")
        .http_service(HttpServiceConfig::default())
        .await
        .expect("service");
    let request = HttpRequest::new("GET", "http://guest.local/tools/call", Vec::new())
        .with_header("url", "http://127.0.0.1:9/denied");
    let error = service.handle(request).await.expect_err("must be denied");
    assert!(error.to_string().contains("denied") || error.to_string().contains("failed"));
}

#[tokio::test]
async fn exact_private_origin_and_method_grant_allows_a_json_tool_call() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("connection");
        let mut request = vec![0; 4096];
        let read = stream.read(&mut request).await.expect("read request");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("POST /tool HTTP/1.1"));
        let body = br#"{"ok":true,"source":"capability-test"}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("write headers");
        stream.write_all(body).await.expect("write body");
    });

    let grant = OutboundHttpGrant::new("http", address.to_string())
        .with_methods(["POST"])
        .with_body_limits(1024, 1024)
        .allow_private_network(true);
    let runtime = Runtime::with_defaults().expect("runtime");
    let service = runtime
        .load_bytes(PROXY_COMPONENT)
        .expect("proxy component")
        .http_service(HttpServiceConfig {
            outbound_grants: vec![grant],
            request_timeout: Duration::from_secs(2),
            ..HttpServiceConfig::default()
        })
        .await
        .expect("service");
    let response = service
        .handle(
            HttpRequest::new(
                "POST",
                "http://guest.local/tools/call",
                br#"{"name":"http","arguments":{"path":"/tool"}}"#,
            )
            .with_header("content-type", "application/json")
            .with_header("url", format!("http://{address}/tool")),
        )
        .await
        .expect("granted response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, br#"{"ok":true,"source":"capability-test"}"#);
    server.await.expect("server task");
}

#[tokio::test]
async fn real_json_tool_requires_and_uses_an_explicit_outbound_capability() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("connection");
        let mut request = vec![0; 4096];
        let read = stream.read(&mut request).await.expect("read request");
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /weather HTTP/1.1"));
        let body = br#"{"temperature_c":21,"condition":"clear"}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("write headers");
        stream.write_all(body).await.expect("write body");
    });

    let runtime = Runtime::with_defaults().expect("runtime");
    let program = runtime
        .load_bytes(JSON_TOOL_COMPONENT)
        .expect("tool component");
    let denied = program
        .http_service(HttpServiceConfig::default())
        .await
        .expect("denied service")
        .handle(HttpRequest::new(
            "POST",
            "http://guest.local/tools/call",
            format!(r#"{{"name":"http_get","arguments":{{"url":"http://{address}/weather"}}}}"#),
        ))
        .await
        .expect("tool returns a structured error");
    assert_eq!(denied.status, 502);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&denied.body).unwrap()["ok"],
        false
    );

    let granted = program
        .http_service(HttpServiceConfig {
            outbound_grants: vec![
                OutboundHttpGrant::new("http", address.to_string())
                    .with_methods(["GET"])
                    .with_body_limits(1, 1024)
                    .allow_private_network(true),
            ],
            ..HttpServiceConfig::default()
        })
        .await
        .expect("granted service")
        .handle(HttpRequest::new(
            "POST",
            "http://guest.local/tools/call",
            format!(r#"{{"name":"http_get","arguments":{{"url":"http://{address}/weather"}}}}"#),
        ))
        .await
        .expect("tool response");
    let result: serde_json::Value = serde_json::from_slice(&granted.body).expect("response JSON");
    assert_eq!(granted.status, 200);
    assert_eq!(result["ok"], true);
    assert_eq!(result["tool"], "http_get");
    assert_eq!(result["result"]["temperature_c"], 21);
    server.await.expect("server task");
}

#[tokio::test]
async fn sleeping_http_guest_is_bounded_by_request_timeout() {
    let runtime = Runtime::with_defaults().expect("runtime");
    let service = runtime
        .load_bytes(SLEEP_COMPONENT)
        .expect("sleep component")
        .http_service(HttpServiceConfig {
            request_timeout: Duration::from_millis(20),
            ..HttpServiceConfig::default()
        })
        .await
        .expect("service");
    let started = Instant::now();
    let error = service
        .handle(HttpRequest::new("GET", "http://guest.local/", Vec::new()))
        .await
        .expect_err("request must expire");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(error.to_string().contains("timed out"));
}
