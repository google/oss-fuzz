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

#![no_main]

use libfuzzer_sys::fuzz_target;

use ttf_parser::{GlyphId, Face, cff};
use std::fmt::Write;

fuzz_target!(|fuzz_data: &[u8]| {
    // Skip this iteration if data is not enough
    if fuzz_data.is_empty() {
        return;
    }

    let choice = fuzz_data[0] % 2;
    let data = &fuzz_data[1..];

    // Randomly choose a module to fuzz
    if (choice) == 0 {
        // Fuzzing CFF1 module
        if let Some(table) = cff::Table::parse(data) {
            let mut builder = Builder(String::new());
            let _ = table.outline(GlyphId(0), &mut builder);
        }
    } else {
        // Fuzzing glyf module
        if let Ok(face) = Face::parse(data, 0) {
            let mut builder = Builder(String::new());
            let _ = face.outline_glyph(GlyphId(0), &mut builder);
        }
    }
});

// Custom Builder implementation
struct Builder(String);

impl ttf_parser::OutlineBuilder for Builder {
    fn move_to(&mut self, x: f32, y: f32) {
        let _ = write!(&mut self.0, "M {} {} ", x, y);
    }

    fn line_to(&mut self, x: f32, y: f32) {
        let _ = write!(&mut self.0, "L {} {} ", x, y);
    }

    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        let _ = write!(&mut self.0, "Q {} {} {} {} ", x1, y1, x, y);
    }

    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        let _ = write!(&mut self.0, "C {} {} {} {} {} {} ", x1, y1, x2, y2, x, y);
    }

    fn close(&mut self) {
        let _ = write!(&mut self.0, "Z ");
    }
}
