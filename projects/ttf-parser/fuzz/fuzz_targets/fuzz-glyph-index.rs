// Copyright 2025 Google LLC
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
// limitations under the License.

// Transformed from ttf-parser/testing-tools/ttf-fuzz/src/fuzz-glyph-index.rs
// for LibFuzzer and Cargo-Fuzz compatibility

#![no_main]

use libfuzzer_sys::fuzz_target;
use ttf_parser::Face;

const CHARS: &[char] = &[
    '\u{0}',
    'A',
    'Ф',
    '0',
    '\u{D7FF}',
    '\u{10FFFF}',
];

fuzz_target!(|data: &[u8]| {
    if let Ok(face) = Face::parse(data, 0) {
        for c in CHARS {
            let _ = face.glyph_index(*c);
        }
    }
});
