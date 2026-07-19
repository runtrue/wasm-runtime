use serde::Deserialize;
use serde_json::{Value, json};
use std::io::Write as _;
use wasip2::{
    exports::http::incoming_handler::Guest,
    http::{
        outgoing_handler,
        types::{
            Fields, IncomingRequest, Method, OutgoingBody, OutgoingRequest, OutgoingResponse,
            ResponseOutparam, Scheme,
        },
    },
    io::streams::StreamError,
};

#[derive(Deserialize)]
struct ToolCall {
    name: String,
    arguments: ToolArguments,
}

#[derive(Deserialize)]
struct ToolArguments {
    url: String,
}

struct JsonHttpTool;

wasip2::http::proxy::export!(JsonHttpTool);

impl Guest for JsonHttpTool {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        let body = match read_incoming_request(request, 64 * 1024) {
            Ok(body) => body,
            Err(reason) => return respond(response_out, 400, error(reason)),
        };
        let call: ToolCall = match serde_json::from_slice(&body) {
            Ok(call) => call,
            Err(reason) => {
                return respond(response_out, 400, error(format!("invalid JSON: {reason}")));
            }
        };
        if call.name != "http_get" {
            return respond(
                response_out,
                400,
                error("unsupported tool; expected http_get"),
            );
        }
        let (upstream_status, upstream_body) = match http_get(&call.arguments.url, 256 * 1024) {
            Ok(response) => response,
            Err(reason) => return respond(response_out, 502, error(reason)),
        };
        let result = serde_json::from_slice(&upstream_body).unwrap_or_else(|_| {
            Value::String(String::from_utf8_lossy(&upstream_body).into_owned())
        });
        respond(
            response_out,
            200,
            json!({
                "ok": true,
                "tool": "http_get",
                "upstream_status": upstream_status,
                "result": result,
            }),
        );
    }
}

fn read_incoming_request(request: IncomingRequest, limit: usize) -> Result<Vec<u8>, String> {
    let body = request
        .consume()
        .map_err(|()| "request body already consumed")?;
    read_stream(
        body.stream().map_err(|()| "request stream unavailable")?,
        limit,
    )
}

fn http_get(url: &str, limit: usize) -> Result<(u16, Vec<u8>), String> {
    let (scheme, remainder) = if let Some(value) = url.strip_prefix("http://") {
        (Scheme::Http, value)
    } else if let Some(value) = url.strip_prefix("https://") {
        (Scheme::Https, value)
    } else {
        return Err("tool URL scheme must be http or https".to_owned());
    };
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, "/".to_owned()), |(authority, path)| {
            (authority, format!("/{path}"))
        });
    if authority.is_empty() || authority.contains('@') {
        return Err("tool URL authority is invalid".to_owned());
    }

    let request = OutgoingRequest::new(Fields::new());
    request
        .set_method(&Method::Get)
        .map_err(|()| "cannot set GET method")?;
    request
        .set_scheme(Some(&scheme))
        .map_err(|()| "cannot set URL scheme")?;
    request
        .set_authority(Some(authority))
        .map_err(|()| "cannot set URL authority")?;
    request
        .set_path_with_query(Some(&path))
        .map_err(|()| "cannot set URL path")?;
    let outgoing_body = request
        .body()
        .map_err(|()| "outgoing request body unavailable")?;
    let future = outgoing_handler::handle(request, None)
        .map_err(|reason| format!("outbound HTTP failed: {reason:?}"))?;
    OutgoingBody::finish(outgoing_body, None)
        .map_err(|reason| format!("outbound HTTP body failed: {reason:?}"))?;
    if future.get().is_none() {
        future.subscribe().block();
    }
    let response = future
        .get()
        .ok_or("outbound HTTP did not complete")?
        .map_err(|()| "outbound HTTP response already consumed")?
        .map_err(|reason| format!("outbound HTTP failed: {reason:?}"))?;
    let status = response.status();
    let body = response
        .consume()
        .map_err(|()| "response body unavailable")?;
    let stream = body.stream().map_err(|()| "response stream unavailable")?;
    Ok((status, read_stream(stream, limit)?))
}

fn read_stream(stream: wasip2::io::streams::InputStream, limit: usize) -> Result<Vec<u8>, String> {
    let pollable = stream.subscribe();
    let mut body = Vec::new();
    loop {
        pollable.block();
        match stream.read(16 * 1024) {
            Ok(chunk) => {
                if body.len().saturating_add(chunk.len()) > limit {
                    return Err(format!("HTTP body exceeds {limit} bytes"));
                }
                body.extend(chunk);
            }
            Err(StreamError::Closed) => return Ok(body),
            Err(reason) => return Err(format!("HTTP body read failed: {reason:?}")),
        }
    }
}

fn error(message: impl Into<String>) -> Value {
    json!({ "ok": false, "error": message.into() })
}

fn respond(response_out: ResponseOutparam, status: u16, value: Value) {
    let headers = Fields::from_list(&[("content-type".to_owned(), b"application/json".to_vec())])
        .expect("static header is valid");
    let response = OutgoingResponse::new(headers);
    response.set_status_code(status).expect("status is valid");
    let body = response.body().expect("response body");
    ResponseOutparam::set(response_out, Ok(response));
    let mut output = body.write().expect("response stream");
    output
        .write_all(&serde_json::to_vec(&value).expect("JSON value serializes"))
        .expect("write response");
    output.flush().expect("flush response");
    drop(output);
    OutgoingBody::finish(body, None).expect("finish response");
}
