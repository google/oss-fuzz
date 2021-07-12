#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate pulldown_cmark;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parser = pulldown_cmark::Parser::new(s);
        for _ in parser {}
    }
});
