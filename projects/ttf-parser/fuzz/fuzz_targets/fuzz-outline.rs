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

// Transformed from ttf-parser/testing-tools/ttf-fuzz/src/fuzz-outline.rs
// for LibFuzzer and Cargo-Fuzz compatibility 

#![no_main]

use libfuzzer_sys::fuzz_target;
use ttf_parser::{Face, GlyphId, OutlineBuilder};

struct Builder(usize);

impl OutlineBuilder for Builder {
    #[inline]
    fn move_to(&mut self, _: f32, _: f32) {
        self.0 += 1;
    }

    #[inline]
    fn line_to(&mut self, _: f32, _: f32) {
        self.0 += 1;
    }

    #[inline]
    fn quad_to(&mut self, _: f32, _: f32, _: f32, _: f32) {
        self.0 += 2;
    }

    #[inline]
    fn curve_to(&mut self, _: f32, _: f32, _: f32, _: f32, _: f32, _: f32) {
        self.0 += 3;
    }

    #[inline]
    fn close(&mut self) {
        self.0 += 1;
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(face) = Face::parse(data, 0) {
        for id in 0..face.number_of_glyphs() {
            let _ = face.outline_glyph(GlyphId(id), &mut Builder(0));
        }
    }
});
