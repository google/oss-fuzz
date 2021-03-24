#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sd) = std::str::from_utf8(data) {
        // limit size cf https://github.com/dtolnay/syn/issues/901
        if sd.len() < 128 {
            syn::parse_str::<syn::Expr>(sd);
        }
    }
});
