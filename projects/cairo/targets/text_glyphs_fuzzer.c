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

const int glyph_range = 9;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < glyph_range) {
        return 0;
    }
    cairo_t *cr;
    cairo_surface_t *surface;
    cairo_status_t status;
    cairo_text_extents_t extents;
    cairo_text_cluster_t cluster;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    surface = cairo_image_surface_create_from_png(tmpfile);
    status = cairo_surface_status(surface);
    if (status != CAIRO_STATUS_SUCCESS) {
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    char *buf = (char *) calloc(size + 1, sizeof(char));
    memcpy(buf, data, size);
    buf[size] = '\0';

    cr = cairo_create(surface);
    cairo_text_extents(cr, buf, &extents);
    cluster.num_bytes = size;
    cluster.num_glyphs = 1;
    for (int i = 0; i < glyph_range; i++) {
        // Taken from test/text-glyph-range.c
        cairo_glyph_t glyph = {
            (long int)data[i], 10 * i, 25
        };
        cairo_show_text_glyphs(cr, buf, size, &glyph, 1, &cluster, 1, 0);
    }

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    free(buf);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
