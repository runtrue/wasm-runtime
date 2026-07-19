use std::io::Write as _;
use wasip2::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

struct Hello;

wasip2::http::proxy::export!(Hello);

impl wasip2::exports::http::incoming_handler::Guest for Hello {
    fn handle(_request: IncomingRequest, response_out: ResponseOutparam) {
        let response = OutgoingResponse::new(Fields::new());
        let body = response.body().expect("response body");
        ResponseOutparam::set(response_out, Ok(response));
        let mut output = body.write().expect("response stream");
        output.write_all(b"Hello, WASI!").expect("write response");
        output.flush().expect("flush response");
        drop(output);
        OutgoingBody::finish(body, None).expect("finish response");
    }
}
