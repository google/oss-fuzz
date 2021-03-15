#![no_main]
use libfuzzer_sys::fuzz_target;
use json5format::*;
use std::str;

fuzz_target!(|data: &[u8]| {
    if let Ok(utf8) = str::from_utf8(data) {
        ParsedDocument::from_str(utf8, None);
    }
});
