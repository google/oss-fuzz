#![no_main]
use libfuzzer_sys::fuzz_target;
use unicode_segmentation::UnicodeSegmentation;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _g = s.graphemes(true).collect::<Vec<&str>>();
        let _w = s.unicode_words().collect::<Vec<&str>>();
        let _ws = s.split_word_bounds().collect::<Vec<&str>>();
    }
});
