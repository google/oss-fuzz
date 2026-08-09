// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.
//
//###################

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;
use std::io::Cursor;

#[derive(Arbitrary, Debug)]
enum ReadOperations<'a> {
    ReadByName(String),
    ReadByNameDecrypt { name: String, password: &'a [u8] },
    ReadByIterableNames,
    ReadByIndex(usize),
    ReadByIndexDecrypt { index: usize, password: &'a [u8] },
    ReadByIterableIndicies,
    ReadComment,
}

#[derive(Arbitrary, Debug)]
#[repr(C)]
struct Driver<'a> {
    // NOTE: we are defining repr(C) so that the struct field ordering is consistent.
    // This consistent ordering means that we still generate a set of zip files
    // for the fuzz corpus, which will become the .zip_file, and any leftover data
    // will be used for structured fuzzing.
    zip_file: &'a [u8],
    read_operations: Vec<ReadOperations<'a>>,
}

fn read_file_attributes(file: &mut zip::read::ZipFile) -> Result<(), zip::result::ZipError> {
    use std::io::Read;
    let _unused = black_box(file.name());
    let _unused = black_box(file.mangled_name());
    let _unused = black_box(file.enclosed_name());
    let _unused = black_box(file.compression());
    let _unused = black_box(file.compressed_size());
    let _unused = black_box(file.size());
    let _unused = black_box(file.last_modified());
    let _unused = black_box(file.is_dir());
    let _unused = black_box(file.is_file());
    let _unused = black_box(file.unix_mode());
    let _unused = black_box(file.crc32());
    let _unused = black_box(file.data_start());
    let _unused = black_box(file.header_start());
    let _unused = black_box(file.central_header_start());
    let mut s: String = String::new();
    let _unused = black_box(file.read_to_string(&mut s));
    return Ok(());
}

fn fuzzed_extract(driver: Driver) -> Result<(), zip::result::ZipError> {
    match zip::ZipArchive::new(Cursor::new(driver.zip_file)) {
        Ok(mut archive) => {
            for operation in driver.read_operations.iter() {
                match operation {
                    ReadOperations::ReadByName(name) => {
                        let mut file = archive.by_name(name)?;
                        let _unused = black_box(read_file_attributes(&mut file));
                    }
                    // TODO: This could probably use a custom mutator, or a specialised seed corpus.
                    // The probability that the fuzzer guesses the correct password is exceedingly low.
                    ReadOperations::ReadByNameDecrypt { name, password } => {
                        match archive.by_name_decrypt(name, password)? {
                            Ok(mut file) => {
                                let _unused = black_box(&read_file_attributes(&mut file));
                            }
                            Err(e) => {
                                let _unused = black_box(format!("{e:?}"));
                                let _unused = black_box(format!("{e:#?}"));
                            }
                        }
                    }
                    ReadOperations::ReadByIterableNames => {
                        let names: Vec<String> =
                            archive.file_names().map(|x| x.to_string()).collect();
                        for name in names.iter() {
                            let mut file = archive.by_name(&name)?;
                            let _unused = black_box(read_file_attributes(&mut file));
                        }
                    }
                    ReadOperations::ReadByIndex(index) => {
                        let mut file = archive.by_index(*index)?;
                        let _unused = black_box(read_file_attributes(&mut file));
                    }
                    ReadOperations::ReadByIndexDecrypt { index, password } => {
                        match archive.by_index_decrypt(*index, password)? {
                            Ok(mut file) => {
                                let _unused = black_box(read_file_attributes(&mut file));
                            }
                            Err(e) => {
                                let _unused = black_box(format!("{e:?}"));
                                let _unused = black_box(format!("{e:#?}"));
                            }
                        }
                    }
                    ReadOperations::ReadByIterableIndicies => {
                        for i in 0..archive.len() {
                            let mut file = archive.by_index(i)?;
                            let _unused = black_box(read_file_attributes(&mut file));
                        }
                    }
                    ReadOperations::ReadComment => {
                        let _unused = black_box(archive.comment());
                    }
                }
            }
        }
        Err(e) => return Err(e),
    }
    return Ok(());
}

fuzz_target!(|driver: Driver| {
    if let Err(e) = fuzzed_extract(driver) {
        let _unused = black_box(format!("{e:?}"));
        let _unused = black_box(format!("{e:#?}"));
    }
});
