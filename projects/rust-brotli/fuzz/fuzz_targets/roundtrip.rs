/*
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::{Read, Write};

fuzz_target!(|data: (u16, u32, u32, &[u8], u16)| {
  let mut compressed = Vec::new();
  let mut writer = brotli::CompressorWriter::new(&mut compressed, data.0.into(), data.1, data.2);
  writer.write_all(data.3).unwrap();
  drop(writer);
  let mut reader = brotli::Decompressor::new(compressed.as_slice(), data.4.into());
  let mut decompressed = Vec::with_capacity(data.3.len());
  let _ = reader.read_to_end(&mut decompressed);
  assert_eq!(data.3, decompressed, "roundtrip failed");
});
