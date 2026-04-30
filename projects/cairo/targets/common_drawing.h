// Copyright 2026 Google LLC
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

#ifndef COMMON_DRAWING_H
#define COMMON_DRAWING_H

#include <cairo.h>
#include <stdint.h>
#include <string.h>

static void do_drawing(cairo_t *cr, const uint8_t *data, size_t size) {
    if (size < 4) return;

    // Use some bytes for color and basic params
    double r = data[0] / 255.0;
    double g = data[1] / 255.0;
    double b = data[2] / 255.0;
    double a = data[3] / 255.0;

    cairo_set_source_rgba(cr, r, g, b, a);
    cairo_set_line_width(cr, (size > 4 ? data[4] : 10) / 10.0);

    size_t offset = 5;
    while (offset + 16 <= size) {
        uint8_t op = data[offset++] % 8;
        double x1 = data[offset++];
        double y1 = data[offset++];
        double x2 = data[offset++];
        double y2 = data[offset++];
        double x3 = data[offset++];
        double y3 = data[offset++];
        
        switch (op) {
            case 0:
                cairo_move_to(cr, x1, y1);
                break;
            case 1:
                cairo_line_to(cr, x1, y1);
                break;
            case 2:
                cairo_curve_to(cr, x1, y1, x2, y2, x3, y3);
                break;
            case 3:
                cairo_rectangle(cr, x1, y1, x2, y2);
                break;
            case 4:
                cairo_arc(cr, x1, y1, x2 / 10.0, 0, 2 * 3.14159);
                break;
            case 5:
                cairo_fill(cr);
                cairo_set_source_rgba(cr, x1/255.0, y1/255.0, x2/255.0, y2/255.0);
                break;
            case 6:
                cairo_stroke(cr);
                break;
            case 7:
                cairo_clip(cr);
                break;
        }
        offset += 10; // skip some bytes to use for next ops
    }
}

#endif
