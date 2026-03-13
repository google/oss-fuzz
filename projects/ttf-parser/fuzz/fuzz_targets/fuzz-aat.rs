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
use std::num::NonZeroU16;
use ttf_parser::{GlyphId, apple_layout::Lookup};

fn u16_to_u8_vec(data: &[u16]) -> Vec<u8> {
    let mut u8_data = Vec::with_capacity(data.len() * 2);
    for &value in data {
        u8_data.push((value >> 8) as u8);
        u8_data.push(value as u8);
    }
    u8_data
}

fuzz_target!(|data: &[u8]| {
    // Skip this iteration if data not enough
    if data.len() < 4 {
        return;
    }

    let (format_data, rest) = data.split_at(2);
    let format = u16::from_be_bytes([format_data[0], format_data[1]]);

    let random_u16 = |data: &[u8], idx: usize| -> Option<u16> {
        if data.len() > idx + 1 {
            Some(u16::from_be_bytes([data[idx], data[idx + 1]]))
        } else {
            None
        }
    };

    let lookup_len = NonZeroU16::new(1).unwrap();

    // Use valid fromat 0 2 4 6 8 10 for fuzzing chioce
    match format {
        0 => {
            if let Some(value) = random_u16(rest, 0) {
                let lookup_data = u16_to_u8_vec(&[0, value]);
                if let Some(table) = Lookup::parse(lookup_len, &lookup_data) {
                    let _ = table.value(GlyphId(0));
                    let _ = table.value(GlyphId(1));
                }
            }
        }
        2 => {
            if let Some(segment_size) = random_u16(rest, 2) {
                let lookup_data = u16_to_u8_vec(&[2, segment_size, 1]);
                if let Some(table) = Lookup::parse(lookup_len, &lookup_data) {
                    let _ = table.value(GlyphId(118));
                    let _ = table.value(GlyphId(5));
                }
            }
        }
        4 => {
            if let Some(segment_size) = random_u16(rest, 2) {
                let lookup_data = u16_to_u8_vec(&[4, segment_size, 1]);
                if let Some(table) = Lookup::parse(lookup_len, &lookup_data) {
                    let _ = table.value(GlyphId(118));
                    let _ = table.value(GlyphId(7));
                }
            }
        }
        6 => {
            if let Some(segment_size) = random_u16(rest, 2) {
                let lookup_data = u16_to_u8_vec(&[6, segment_size]);
                if let Some(table) = Lookup::parse(lookup_len, &lookup_data) {
                    let _ = table.value(GlyphId(0));
                    let _ = table.value(GlyphId(10));
                }
            }
        }
        8 => {
            if let Some(glyph_count) = random_u16(rest, 2) {
                let lookup_data = u16_to_u8_vec(&[8, 0, glyph_count]);
                if let Some(table) = Lookup::parse(lookup_len, &lookup_data) {
                    let _ = table.value(GlyphId(0));
                    let _ = table.value(GlyphId(5));
                }
            }
        }
        10 => {
            if let Some(value_size) = random_u16(rest, 2) {
                let lookup_data = u16_to_u8_vec(&[10, value_size, 0]);
                if let Some(table) = Lookup::parse(lookup_len, &lookup_data) {
                    let _ = table.value(GlyphId(0));
                    let _ = table.value(GlyphId(1));
                }
            }
        }
        _ => {
          // Ignore invliad format of 1 3 5 7 9        
        }
    }
});
