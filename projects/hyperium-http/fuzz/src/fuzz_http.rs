#![no_main]

use libfuzzer_sys::fuzz_target;
extern crate http;
use http::Request;
use std::str;

fuzz_target!(|data: &[u8]| {
    let request = Request::builder().uri(data).header(data, data).body(());
});

