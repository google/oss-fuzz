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
use ttf_parser::{colr, GlyphId, cpal, RgbaColor};

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    // Fuzz CPAL/COLR parse
    if let Some(cpal_table) = cpal::Table::parse(data) {
        if let Some(colr_table) = colr::Table::parse(cpal_table, data) {
            let mut painter = VecPainter(vec![]);
            let glyph_id = GlyphId(data[0] as u16);
            let _ = colr_table.paint(glyph_id, 0, &mut painter, &[], RgbaColor::new(0, 0, 0, 255));
        }
    }
});

// Custom VecPainter
struct VecPainter(Vec<Command>);

impl<'a> colr::Painter<'a> for VecPainter {
    fn outline_glyph(&mut self, glyph_id: GlyphId) {
        self.0.push(Command::OutlineGlyph(glyph_id));
    }

    fn paint(&mut self, paint: colr::Paint<'a>) {
        let custom_paint = match paint {
            colr::Paint::Solid(color) => CustomPaint::Solid(color),
            colr::Paint::LinearGradient(lg) => CustomPaint::LinearGradient(
                lg.x0, lg.y0, lg.x1, lg.y1, lg.x2, lg.y2, lg.extend,
                lg.stops(0, &[]).map(|stop| CustomStop(stop.stop_offset, stop.color)).collect(),
            ),
            colr::Paint::RadialGradient(rg) => CustomPaint::RadialGradient(
                rg.x0, rg.y0, rg.r0, rg.r1, rg.x1, rg.y1, rg.extend,
                rg.stops(0, &[]).map(|stop| CustomStop(stop.stop_offset, stop.color)).collect(),
            ),
            colr::Paint::SweepGradient(sg) => CustomPaint::SweepGradient(
                sg.center_x, sg.center_y, sg.start_angle, sg.end_angle, sg.extend,
                sg.stops(0, &[]).map(|stop| CustomStop(stop.stop_offset, stop.color)).collect(),
            ),
        };

        self.0.push(Command::Paint(custom_paint));
    }

    fn push_layer(&mut self, mode: colr::CompositeMode) {
        self.0.push(Command::PushLayer(mode));
    }

    fn pop_layer(&mut self) {
        self.0.push(Command::PopLayer);
    }

    fn push_transform(&mut self, transform: ttf_parser::Transform) {
        self.0.push(Command::Transform(transform));
    }

    fn pop_transform(&mut self) {
        self.0.push(Command::PopTransform);
    }

    fn push_clip(&mut self) {
        self.0.push(Command::PushClip);
    }

    fn push_clip_box(&mut self, clipbox: colr::ClipBox) {
        self.0.push(Command::PushClipBox(clipbox));
    }

    fn pop_clip(&mut self) {
        self.0.push(Command::PopClip);  
    }
}

#[derive(Clone, Debug, PartialEq)]
struct CustomStop(f32, RgbaColor);

#[derive(Clone, Debug, PartialEq)]
enum CustomPaint {
    Solid(RgbaColor),
    LinearGradient(f32, f32, f32, f32, f32, f32, colr::GradientExtend, Vec<CustomStop>),
    RadialGradient(f32, f32, f32, f32, f32, f32, colr::GradientExtend, Vec<CustomStop>),
    SweepGradient(f32, f32, f32, f32, colr::GradientExtend, Vec<CustomStop>),
}

#[derive(Clone, Debug, PartialEq)]
enum Command {
    OutlineGlyph(GlyphId),
    Paint(CustomPaint),
    PushLayer(colr::CompositeMode),
    PopLayer,
    Transform(ttf_parser::Transform),
    PopTransform,
    PushClip,
    PushClipBox(colr::ClipBox),
    PopClip,
}
