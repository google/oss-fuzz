// Copyright 2020 Google LLC
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
#include "fuzzer_temp_file.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cairo_t *cr;
    cairo_surface_t *surface;
    cairo_status_t status;
    cairo_text_extents_t extents;
    cairo_text_cluster_t cluster;

    // Taken from test/text-glyph-range.c
    long int index[] = {
        0, /* 'no matching glyph' */
        0xffff, /* kATSDeletedGlyphCode */
        0x1ffff, /* out of range */
        -1L, /* out of range */
        70, 68, 76, 85, 82 /* 'cairo' */
    };

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    surface = cairo_image_surface_create_from_png(tmpfile);
    status = cairo_surface_status(surface);
    if (status != CAIRO_STATUS_SUCCESS) {
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    char *buf = (char *) malloc(size + 1);
    memcpy(buf, data, size);
    buf[size] = '\0';

    cr = cairo_create(surface);
    cairo_text_extents(cr, buf, &extents);
    cluster.num_bytes = size;
    cluster.num_glyphs = 1;
    for (int i = 0; i < 9; i++) {
        // Taken from test/text-glyph-range.c
        cairo_glyph_t glyph = {
            index[i], 10 * i, 25
        };
        cairo_show_text_glyphs(cr, buf, size, &glyph, 1, &cluster, 1, 0);
    }

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    free(buf);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
