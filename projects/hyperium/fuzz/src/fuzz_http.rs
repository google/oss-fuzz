#![no_main]

use libfuzzer_sys::fuzz_target;
extern crate http;
use http::Request;
use http::StatusCode;
use http::Response;

use libfuzzer_sys::arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct HttpSpec {
        uri: Vec<u8>,
        header_name: Vec<u8>,
        header_value: Vec<u8>,
        status_codes: Vec<u8>,
        response: Vec<u8>,
}


fuzz_target!(|inp: HttpSpec|  {
    let _ = Request::builder()
                    .uri(&inp.uri[..])
                    .header(&inp.header_name[..], &inp.header_value[..])
                    .body(());

    let _ = Response::builder()
                        .header(&inp.header_name[..], &inp.header_value[..])
                        .body(&inp.response[..]);
    let _ = StatusCode::from_bytes(&inp.status_codes[..]);
});

