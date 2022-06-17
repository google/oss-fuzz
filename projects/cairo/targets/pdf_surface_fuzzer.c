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
#include <cairo-pdf.h>
#include "fuzzer_temp_file.h"

const double width_in_inches = 3;
const double height_in_inches = 3;
const double width_in_points = width_in_inches * 72.0;
const double height_in_points = height_in_inches * 72.0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cairo_t *cr;
    cairo_surface_t *surface;
    cairo_status_t status;

    if (size == 0) {
        return 0;
    }

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    surface = cairo_pdf_surface_create(tmpfile, width_in_points, height_in_points);
    status = cairo_surface_status(surface);
    if (status != CAIRO_STATUS_SUCCESS) {
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    char *buf = (char *) calloc(size + 1, sizeof(char));
    memcpy(buf, data, size);
    buf[size] = '\0';

    cairo_pdf_surface_set_metadata(surface, CAIRO_PDF_METADATA_TITLE, buf);
    cr = cairo_create(surface);
    cairo_tag_begin(cr, buf, NULL);
    cairo_tag_end(cr, buf);

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    free(buf);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
