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
use ttf_parser::{GlyphId};
use ttf_parser::{ankr, avar, cmap, feat, fvar, gdef, gvar, hmtx, hvar, kern, kerx};
use ttf_parser::{loca, math, maxp, morx, mvar, name, sbix, stat, svg, trak, vhea, vorg, vvar};

fuzz_target!(|fuzz_data: &[u8]| {
    // Skip this iteration if data is empty
    if fuzz_data.is_empty() {
        return;
    }

    // Randomly choose a fuzzing target function
    let choice = fuzz_data[0] % 26;
    let data = &fuzz_data[1..];
    match choice {
        0 => {
            // Fuzz cmap module
            if let Some(subtable0) = cmap::Subtable0::parse(data) {
                subtable0.glyph_index(0x41);
                subtable0.glyph_index(0x42);
                let mut codepoints = vec![];
                subtable0.codepoints(|c| codepoints.push(c));
            }
            if let Some(subtable4) = cmap::Subtable4::parse(data) {
                subtable4.glyph_index(0x41);
                subtable4.glyph_index(0x42);
                let mut codepoints = vec![];
                subtable4.codepoints(|c| codepoints.push(c));
            }
        }
        1 => {
            // Fuzz ankr module
            if let Some(table) = ankr::Table::parse(NonZeroU16::new(1).unwrap(), data) {
                if let Some(points) = table.points(GlyphId(0)) {
                    for point in points {
                        let _ = point.x;
                        let _ = point.y;
                    }
                }
            }
        }
        2 => {
            // Fuzz feat module
            if let Some(feat_table) = feat::Table::parse(data) {
                for feature in feat_table.names {
                    let _ = feature.exclusive;
                    let _ = feature.default_setting_index;
                }
            }
        }
        3 => {
            // Fuzz hmtx module
            if let Some(hmtx_table) = hmtx::Table::parse(1, NonZeroU16::new(1).unwrap(), data) {
                let _ = hmtx_table.number_of_metrics;
            }
        }
        4 => {
            // Fuzz maxp module
            if let Some(maxp_table) = maxp::Table::parse(data) {
                let _ = maxp_table.number_of_glyphs;
            }
        }
        5 => {
            // Fuzz sbix module
            if let Some(table) = sbix::Table::parse(NonZeroU16::new(1).unwrap(), data) {
                for strike in table.strikes {
                    for i in 0..strike.len() {
                        if let Some(glyph_data) = strike.get(GlyphId(i as u16)) {
                            let _ = glyph_data.x;
                            let _ = glyph_data.y;
                            let _ = glyph_data.width;
                            let _ = glyph_data.height;
                            let _ = glyph_data.pixels_per_em;
                            let _ = glyph_data.format;
                        }
                    }
                }
            }
        }
        6 => {
            // Fuzz trak module
            if let Some(trak_table) = trak::Table::parse(data) {
                for track in trak_table.horizontal.tracks {
                    let _ = track.value;
                    for value in track.values {
                        let _ = value;
                    }
                }
            }
        }
        7 => {
            // Fuzz kern module
            if let Some(kern_table) = kern::Table::parse(data) {
                for subtable in kern_table.subtables.into_iter() {
                    if let Some(kern_val) = subtable.glyphs_kerning(GlyphId(1), GlyphId(2)) {
                        let _ = kern_val;
                    }
                }
            }
        }
        8 => {
            // Fuzz kerx module
            if let Some(kerx_table) = kerx::Table::parse(NonZeroU16::new(1).unwrap(), data) {
                for subtable in kerx_table.subtables.into_iter() {
                    if let Some(kerx_val) = subtable.glyphs_kerning(GlyphId(1), GlyphId(2)) {
                        let _ = kerx_val;
                    }
                }
            }
        }
        9 => {
            // Fuzz loca module
            if let Some(loca_table) = loca::Table::parse(NonZeroU16::new(1).unwrap(), ttf_parser::head::IndexToLocationFormat::Short, data) {
                if let Some(range) = loca_table.glyph_range(GlyphId(1)) {
                    let _ = range.start;
                    let _ = range.end;
                }
            }
        }
        10 => {
            // Fuzz math constants module
            if let Some(math_table) = math::Table::parse(data) {
                if let Some(constants) = math_table.constants {
                    let _ = constants.axis_height();
                    let _ = constants.script_percent_scale_down();
                }
            }
        }
        11 => {
            // Fuzz math kern info module
            if let Some(math_table) = math::Table::parse(data) {
                if let Some(glyph_info) = math_table.glyph_info {
                    if let Some(kern_infos) = glyph_info.kern_infos {
                        if let Some(kern_info) = kern_infos.get(GlyphId(1)) {
                            let _ = kern_info.top_right;
                            let _ = kern_info.bottom_left;
                        }
                    }
                }
            }
        }
        12 => {
            // Fuzz gvar module
            let _ = gvar::Table::parse(data);
        }
        13 => {
            // Fuzz hvar module
            let _ = hvar::Table::parse(data);
        }
        14 => {
            // Fuzz avar module
            let _ = avar::Table::parse(data);
        }
        15 => {
            // Fuzz fvar module
            if let Some(fvar_table) = fvar::Table::parse(data) {
                for axis in fvar_table.axes {
                    let _ = axis.tag;
                }
            }
        }
        16 => {
            // Fuzz gdef module
            if let Some(gdef_table) = gdef::Table::parse(data) {
                let _ = gdef_table.glyph_class(GlyphId(1));
            }
        }
        17 => {
            // Fuzz morx module
            if let Some(morx_table) = morx::Table::parse(NonZeroU16::new(1).unwrap(), data) {
                for chain in morx_table.chains {
                    let _ = chain.default_flags;
                    for feature in chain.features {
                        let _ = feature.kind;
                    }
                }
            }
        }
        18 => {
            // Fuzz mvar module
            if let Some(mvar_table) = mvar::Table::parse(data) {
                let _ = mvar_table.metric_offset(ttf_parser::Tag::from_bytes(b"wdth"), &[]);
            }
        }
        19 => {
            // Fuzz name module
            if let Some(name_table) = name::Table::parse(data) {
                for index in 0..name_table.names.len() {
                    if let Some(name) = name_table.names.get(index) {
                        let _ = name.to_string();
                    }
                }
            }
        }
        20 => {
            // Fuzz stat module
            if let Some(stat_table) = stat::Table::parse(data) {
                for subtable in stat_table.subtables() {
                    let _ = subtable.name_id();
                }
            }
        }
        21 => {
            // Fuzz svg module
            if let Some(svg_table) = svg::Table::parse(data) {
                for index in 0..svg_table.documents.len() {
                    if let Some(svg_doc) = svg_table.documents.get(index) {
                        let _ = svg_doc.glyphs_range();
                    }
                }
            }
        }
        22 => {
            // Fuzz trak module
            if let Some(trak_table) = trak::Table::parse(data) {
                for track in trak_table.horizontal.tracks {
                    let _ = track.value;
                    for value in track.values {
                        let _ = value;
                    }
                }
            }
        }
        23 => {
            // Fuzz vhea module
            if let Some(vhea_table) = vhea::Table::parse(data) {
                let _ = vhea_table.ascender;
                let _ = vhea_table.descender;
                let _ = vhea_table.line_gap;
                let _ = vhea_table.number_of_metrics;
            }
        }
        24 => {
            // Fuzz vorg module
            if let Some(vorg_table) = vorg::Table::parse(data) {
                let _ = vorg_table.default_y;
                for metrics in vorg_table.metrics {
                    let _ = metrics.glyph_id;
                    let _ = metrics.y;
                }
            }
        }
        25 => {
            // Fuzz vvar module
            if let Some(vvar_table) = vvar::Table::parse(data) {
                let _ = vvar_table.advance_offset(GlyphId(1), &[]);
                let _ = vvar_table.top_side_bearing_offset(GlyphId(1), &[]);
                let _ = vvar_table.bottom_side_bearing_offset(GlyphId(1), &[]);
                let _ = vvar_table.vertical_origin_offset(GlyphId(1), &[]);
            }
        }
        _ => {}
    }
});
