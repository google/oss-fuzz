#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Seek};
use zip::CompressionMethod;
use zip::write::FileOptions;
use std::fs::File;
use std::io::Write;
use std::fs;


fuzz_target!(|data: &[u8]| {
    match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(archive) => {
            for i in 0..archive.len() {
                let comment = archive.comment();
                if !comment.is_empty() {
                }

            }
        },
        Err(e) =>  return
    }
});
