#![no_main]

extern crate proto;

use libfuzzer_sys::fuzz_target;
use proto::{Side, fuzzing::TransportParameters};

fuzz_target!(|data: &[u8]| {
    // Try parsing as both client and server parameters
    let mut buf = bytes::Bytes::copy_from_slice(data);
    let _ = TransportParameters::read(Side::Client, &mut buf);

    let mut buf = bytes::Bytes::copy_from_slice(data);
    let _ = TransportParameters::read(Side::Server, &mut buf);
});
