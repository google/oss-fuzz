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

use arbitrary::{self, Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;
use zip::{self, result::ZipError};

fn arbitrary_unix_permissions(u: &mut Unstructured) -> arbitrary::Result<u32> {
    return Ok(u.int_in_range(0o1..=0o777)?);
}

// Generate a valid arbitrary path.
fn arbitrary_path(u: &mut Unstructured) -> arbitrary::Result<String> {
    let path_len: usize = u.int_in_range(1..=512).unwrap_or(1);
    Ok((0..=path_len)
        .map(|_| {
            let valid_chars: Vec<char> = ('a'..='z')
                .chain('A'..='Z')
                .chain("/-_.@".chars())
                .collect();
            return valid_chars[u.choose_index(valid_chars.len()).unwrap_or(0)];
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq)]
struct Compression {
    method: zip::CompressionMethod,
    level: Option<i32>,
}

impl<'a> Arbitrary<'a> for Compression {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        use zip::CompressionMethod::*;
        Ok(match u8::arbitrary(u) {
            Ok(1) => Compression {
                method: Stored,
                level: u.int_in_range(0..=9).ok(),
            },
            Ok(2) => Compression {
                method: Deflated,
                level: u.int_in_range(0..=9).ok(),
            },
            Ok(3) => Compression {
                method: Bzip2,
                level: u.int_in_range(1..=9).ok(),
            },
            _ => Compression {
                method: Zstd,
                level: u.int_in_range(-7..=22).ok(),
            },
        })
    }
}

fn arbitrary_file(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let file = Vec::<u8>::arbitrary(u)?;
    if file.len() == 0 {
        return Err(arbitrary::Error::IncorrectFormat);
    }
    return Ok(file);
}

#[derive(Arbitrary, Clone, Debug, PartialEq)]
struct File {
    #[arbitrary(with = arbitrary_path)]
    zip_path: String,
    #[arbitrary(with = arbitrary_file)]
    contents: Vec<u8>,
    compression: Compression,
    alignment: Option<u16>,
    large_file: bool,
    #[arbitrary(with = arbitrary_unix_permissions)]
    unix_permissions: u32,
}

#[derive(Arbitrary, Clone, Debug, PartialEq)]
enum ZipEntry<'a> {
    File(File),
    RawComment(&'a [u8]),
    Comment(String),
    Symlink {
        #[arbitrary(with = arbitrary_path)]
        src: String,
        #[arbitrary(with = arbitrary_path)]
        dst: String,
    },
    Directory {
        #[arbitrary(with = arbitrary_path)]
        path: String,
    },
}

impl<'a> ZipEntry<'a> {
    fn path(&self) -> Option<String> {
        match self {
            ZipEntry::File(file) => Some(file.zip_path.clone()),
            ZipEntry::Symlink { dst, .. } => Some(dst.clone()),
            ZipEntry::Directory { path } => Some(path.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
struct Operations<'a> {
    zip_entries: Vec<ZipEntry<'a>>,
}

impl<'a> Arbitrary<'a> for Operations<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let zip_entries = Vec::<ZipEntry>::arbitrary(u)?;
        let mut paths = std::collections::HashSet::new();
        let mut result = Vec::new();
        for zip_entry in zip_entries.iter() {
            if let Some(path) = zip_entry.path() {
                if paths.contains(&path) {
                    continue;
                } else {
                    result.push(zip_entry.clone());
                    paths.insert(path.clone());
                }
            } else {
                result.push(zip_entry.clone());
            }
        }
        return Ok(Operations {
            zip_entries: result,
        });
    }
}

fn build_zip(zip_entries: &Vec<ZipEntry>) -> Result<Vec<u8>, ZipError> {
    use std::io::Write;
    use zip::write::FileOptions;

    // 1mB
    let max_zip_size = 1024 * 1024 * 1;
    let mut buf = vec![0; max_zip_size];
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf[..]));

    let mut created_paths = std::collections::HashSet::new();
    for entry in zip_entries.iter() {
        use ZipEntry::*;
        match entry {
            File(file) => {
                if created_paths.contains(&file.zip_path) {
                    continue;
                } else {
                    created_paths.insert(file.zip_path.clone());
                }
                let options = FileOptions::default()
                    .compression_method(file.compression.method)
                    .compression_level(file.compression.level)
                    .large_file(file.large_file)
                    .unix_permissions(file.unix_permissions);
                if let Some(alignment) = file.alignment {
                    zip.start_file_aligned(file.zip_path.clone(), options, alignment)?;
                } else {
                    zip.start_file(file.zip_path.clone(), options)?;
                }

                zip.write(&file.contents)?;
            }
            RawComment(comment) => zip.set_raw_comment(comment.to_vec()),
            Comment(comment) => zip.set_comment(comment),
            Symlink { src, dst } => {
                if created_paths.contains(dst) {
                    continue;
                } else {
                    created_paths.insert(dst.clone());
                }
                let options = FileOptions::default();
                zip.add_symlink(dst, src, options)?;
            }
            Directory { path } => {
                if created_paths.contains(path) {
                    continue;
                } else {
                    created_paths.insert(path.clone());
                }
                let options = FileOptions::default();
                zip.add_directory(path, options)?;
            }
        }
    }

    return Ok(zip.finish()?.get_ref().to_vec());
}

fuzz_target!(|operations: Operations| {
    match build_zip(&operations.zip_entries) {
        Ok(compressed) => match zip::ZipArchive::new(std::io::Cursor::new(compressed)) {
            Ok(mut archive) => {
                for i in 0..archive.len() {
                    let mut file = archive
                        .by_index(i)
                        .expect("This was a generated zip it should be valid.");
                    let _ = std::io::copy(&mut file, &mut std::io::sink());
                }
            }
            Err(e) => {
                let _unused = black_box(format!("{e:?}"));
                let _unused = black_box(format!("{e:#?}"));
            }
        },
        Err(e) => {
            let _unused = black_box(format!("{e:?}"));
            let _unused = black_box(format!("{e:#?}"));
        }
    }
});
