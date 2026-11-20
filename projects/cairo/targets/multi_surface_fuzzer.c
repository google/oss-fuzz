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
#include <cairo-svg.h>
#include <cairo-script.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "common_drawing.h"

static cairo_status_t
_write_func (void *closure, const uint8_t *data, unsigned int length)
{
    return CAIRO_STATUS_SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    uint8_t backend_choice = data[0] % 4;
    const uint8_t *fuzz_data = data + 1;
    size_t fuzz_size = size - 1;

    cairo_surface_t *surface = NULL;
    cairo_device_t *device = NULL;
    cairo_status_t status;

    switch (backend_choice) {
        case 0: // PDF
            surface = cairo_pdf_surface_create_for_stream(_write_func, NULL, 500.0, 500.0);
            break;
        case 1: // PS
            surface = cairo_ps_surface_create_for_stream(_write_func, NULL, 595.0, 842.0); // A4
            break;
        case 2: // SVG
            surface = cairo_svg_surface_create_for_stream(_write_func, NULL, 500.0, 500.0);
            break;
        case 3: // Script
            device = cairo_script_create_for_stream(_write_func, NULL);
            if (cairo_device_status(device) == CAIRO_STATUS_SUCCESS) {
                surface = cairo_script_surface_create(device, CAIRO_CONTENT_COLOR_ALPHA, 400, 400);
            }
            break;
    }

    if (!surface || cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
        if (surface) cairo_surface_destroy(surface);
        if (device) cairo_device_destroy(device);
        return 0;
    }

    cairo_t *cr = cairo_create(surface);
    
    // Backend specific exercises
    if (backend_choice == 0 && fuzz_size > 0) { // PDF specific
        char *buf = (char *) malloc(fuzz_size + 1);
        if (buf) {
            memcpy(buf, fuzz_data, fuzz_size);
            buf[fuzz_size] = '\0';
            cairo_pdf_surface_set_metadata(surface, CAIRO_PDF_METADATA_TITLE, buf);
            cairo_tag_begin(cr, buf, NULL);
            cairo_tag_end(cr, buf);
            free(buf);
        }
    }

    do_drawing(cr, fuzz_data, fuzz_size);

    if (backend_choice != 3) {
        cairo_show_page(cr);
    }

    cairo_destroy(cr);
    cairo_surface_finish(surface);
    cairo_surface_destroy(surface);
    
    if (device) {
        cairo_device_finish(device);
        cairo_device_destroy(device);
    }

    return 0;
}
