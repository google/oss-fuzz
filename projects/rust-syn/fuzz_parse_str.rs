#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sd) = std::str::from_utf8(data) {
        syn::parse_str::<syn::Expr>(sd);
    }
});
