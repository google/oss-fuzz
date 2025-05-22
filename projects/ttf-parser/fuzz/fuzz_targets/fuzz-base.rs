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
use ttf_parser::{Face, GlyphId, name_id};

fn get_fuzzed_char(data: &[u8]) -> char {
    if data.len() >= 4 {
        let code_point = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        std::char::from_u32(code_point).unwrap_or('A')
    } else {
        'A'
    }
}

fuzz_target!(|data: &[u8]| {
    // Skip this iteration if no data is provided
    if data.is_empty() {
        return;
    }

    let choice = data[0] % 15;
    let fuzz_data = &data[1..];

    let face_result = Face::parse(fuzz_data, 0);
    let id = if !data.is_empty() { data[0] as u16 } else { 0 };
    let glyph_id = GlyphId(id);
    let random_char = get_fuzzed_char(fuzz_data);

    // Randomly fuzz functions from base ttf-parser
    match choice {
        0 => {
            if let Ok(face) = face_result {
                let mut family_names = Vec::new();
                for name in face.names() {
                    if name.name_id == name_id::FULL_NAME && name.is_unicode() {
                        if let Some(family_name) = name.to_string() {
                            let language = name.language();
                            family_names.push(format!(
                                "{} ({}, {})",
                                family_name,
                                language.primary_language(),
                                language.region()
                            ));
                        }
                    }
                }
                let _ = family_names;
            }
        },
        1 => {
            if let Ok(face) = face_result {
                let _ = face.units_per_em();
                let _ = face.ascender();
                let _ = face.descender();
                let _ = face.line_gap();
                let _ = face.global_bounding_box();
            }
        },
        2 => {
            if let Ok(face) = face_result {
                let _ = face.is_regular();
                let _ = face.is_bold();
                let _ = face.is_italic();
                let _ = face.is_oblique();
                let _ = face.is_variable();
            }
        },
        3 => {
            if let Ok(face) = face_result {
                let _ = face.number_of_glyphs();
                let _ = face.glyph_bounding_box(glyph_id);
                let _ = face.glyph_hor_advance(glyph_id);
                let _ = face.glyph_index(random_char);
            }
        },
        4 => {
            if let Ok(face) = face_result {
                let _ = face.underline_metrics();
                let _ = face.strikeout_metrics();
                let _ = face.subscript_metrics();
                let _ = face.superscript_metrics();
            }
        },
        5 => {
            if let Ok(face) = face_result {
                let post_script_name = face.names().into_iter()
                    .find(|name| name.name_id == name_id::POST_SCRIPT_NAME && name.is_unicode())
                    .and_then(|name| name.to_string());
                let _ = post_script_name;
            }
        },
        6 => { 
            if let Ok(face) = face_result {
                let _ = face.glyph_raster_image(glyph_id, u16::MAX);
            }
        },
        7 => {
            if let Ok(face) = face_result {
                if let Some(stat) = face.tables().stat {
                    for axis in stat.axes {
                        let _ = axis.tag;
                    }
                }
            }
        },
        8 => {
            if let Ok(face) = face_result {
                if let Some(svg_table) = face.tables().svg {
                    let _ = svg_table.documents.find(glyph_id);
                }
            }
        },
        9 => {
            if let Ok(face) = face_result {
                let _ = face.permissions();
                let _ = face.is_variable();
            }
        },
        10 => {
            if let Ok(face) = face_result {
                let _ = face.glyph_hor_side_bearing(glyph_id);
                let _ = face.glyph_ver_advance(glyph_id);
                let _ = face.glyph_ver_side_bearing(glyph_id);
            }
        },
        11 => {
            if let Ok(face) = face_result {
                let _ = face.tables().os2;
            }
        },
        12 => {
            if let Ok(face) = face_result {
                let _ = face.tables().head;
            }
        },
        13 => {
            if let Ok(face) = face_result {
                let _ = face.tables().maxp;
            }
        },
        14 => {
            if let Ok(face) = face_result {
                let _ = face.tables().hhea;
            }
        },
        _ => return,
    }
});
