#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate html_escape;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        html_escape::decode_style_quoted_text(s);
        html_escape::decode_style_quoted_text_to_string(s, &mut String::new());
        let mut v1 = Vec::new();
        html_escape::decode_script_quoted_text_to_writer(s, &mut v1);

        html_escape::encode_script(s);
        html_escape::encode_script_quoted_text(s);
        let mut v2 = Vec::new();
        html_escape::encode_style_quoted_text_to_writer(s, &mut v2);
        html_escape::encode_style_quoted_text_to_string(s, &mut String::new());
    }
});
