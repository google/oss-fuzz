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
    cairo_surface_t *image;
    cairo_surface_t *surface;
    cairo_status_t status;
    cairo_format_t format;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    image = cairo_image_surface_create_from_png(tmpfile);
    status = cairo_surface_status (image);
    if (status != CAIRO_STATUS_SUCCESS) {
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    format = cairo_image_surface_get_format(image);
    surface = cairo_image_surface_create_for_data((unsigned char*)data, format, 1, 1, size);
    status = cairo_surface_status (surface);
    if (status != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(image);
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }
    cairo_surface_write_to_png(surface, tmpfile);

    cairo_surface_destroy(surface);
    cairo_surface_destroy(image);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
