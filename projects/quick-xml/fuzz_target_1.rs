#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate quick_xml;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    use quick_xml::Reader;
    use std::io::Cursor;

    let cursor = Cursor::new(data);
    let mut reader = Reader::from_reader(cursor);
    let mut buf = vec![];
    loop {
        match reader.read_event(&mut buf) {
            Ok(quick_xml::events::Event::Eof) | Err(..) => break,
            _ => buf.clear(),
        }
    }
});

