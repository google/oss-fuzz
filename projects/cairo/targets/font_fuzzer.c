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

#include <cairo.h>
#include <cairo-pdf.h>
#include <cairo-ps.h>
#include <cairo-ft.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static cairo_status_t
_write_func (void *closure, const uint8_t *data, unsigned int length)
{
    return CAIRO_STATUS_SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 100) return 0;

    FT_Library library;
    if (FT_Init_FreeType(&library)) return 0;

    FT_Face face;
    if (FT_New_Memory_Face(library, data, size, 0, &face)) {
        FT_Done_FreeType(library);
        return 0;
    }

    cairo_font_face_t *font_face = cairo_ft_font_face_create_for_ft_face(face, 0);
    if (cairo_font_face_status(font_face) != CAIRO_STATUS_SUCCESS) {
        cairo_font_face_destroy(font_face);
        FT_Done_Face(face);
        FT_Done_FreeType(library);
        return 0;
    }

    // 1. Fuzz PDF font subsetting
    cairo_surface_t *pdf_surface = cairo_pdf_surface_create_for_stream(_write_func, NULL, 100, 100);
    cairo_t *cr_pdf = cairo_create(pdf_surface);
    cairo_set_font_face(cr_pdf, font_face);
    cairo_set_font_size(cr_pdf, 12);
    cairo_move_to(cr_pdf, 10, 50);
    cairo_show_text(cr_pdf, "Fuzzing PDF font subsetting");
    cairo_show_page(cr_pdf);
    cairo_destroy(cr_pdf);
    cairo_surface_finish(pdf_surface);
    cairo_surface_destroy(pdf_surface);

    // 2. Fuzz PS font subsetting
    cairo_surface_t *ps_surface = cairo_ps_surface_create_for_stream(_write_func, NULL, 100, 100);
    cairo_t *cr_ps = cairo_create(ps_surface);
    cairo_set_font_face(cr_ps, font_face);
    cairo_set_font_size(cr_ps, 12);
    cairo_move_to(cr_ps, 10, 50);
    cairo_show_text(cr_ps, "Fuzzing PS font subsetting");
    cairo_show_page(cr_ps);
    cairo_destroy(cr_ps);
    cairo_surface_finish(ps_surface);
    cairo_surface_destroy(ps_surface);

    // 3. Fuzz COLR glyph rendering on image surface
    cairo_surface_t *image_surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 100, 100);
    cairo_t *cr_img = cairo_create(image_surface);
    
    cairo_font_options_t *font_options = cairo_font_options_create();
    cairo_font_options_set_color_mode(font_options, CAIRO_COLOR_MODE_COLOR);
    cairo_set_font_options(cr_img, font_options);
    cairo_font_options_destroy(font_options);

    cairo_set_font_face(cr_img, font_face);
    cairo_set_font_size(cr_img, 50);

    // Try some glyph indices from the input
    cairo_glyph_t glyphs[8];
    int num_glyphs = 0;
    size_t glyph_data_offset = size > 200 ? 100 : 0; // Use some data for glyph indices if enough
    if (size >= glyph_data_offset + 8 * sizeof(uint32_t)) {
        const uint32_t *u32 = (const uint32_t *)(data + glyph_data_offset);
        for (int i = 0; i < 8; i++) {
            glyphs[i].index = u32[i] % 65536; 
            glyphs[i].x = (i % 4) * 25;
            glyphs[i].y = (i / 4) * 50 + 25;
            num_glyphs++;
        }
        cairo_show_glyphs(cr_img, glyphs, num_glyphs);
    } else {
        cairo_move_to(cr_img, 10, 50);
        cairo_show_text(cr_img, "ABC");
    }

    cairo_destroy(cr_img);
    cairo_surface_destroy(image_surface);

    cairo_font_face_destroy(font_face);
    FT_Done_Face(face);
    FT_Done_FreeType(library);

    return 0;
}
