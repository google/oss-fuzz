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
#include <cairo-script-interpreter.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static cairo_surface_t *
_surface_create (void *closure,
		 cairo_content_t content,
		 double width, double height,
		 long uid)
{
    // Limit size to avoid excessive memory usage
    if (width <= 0 || width > 4096) width = 100;
    if (height <= 0 || height > 4096) height = 100;
    return cairo_image_surface_create (CAIRO_FORMAT_ARGB32, width, height);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cairo_script_interpreter_t *csi;
    const cairo_script_interpreter_hooks_t hooks = {
        .surface_create = _surface_create
    };

    if (size == 0) {
        return 0;
    }

    csi = cairo_script_interpreter_create();
    if (!csi) {
        return 0;
    }
    
    cairo_script_interpreter_install_hooks (csi, &hooks);

    cairo_script_interpreter_feed_string(csi, (const char *)data, size);

    cairo_script_interpreter_finish(csi);
    cairo_script_interpreter_destroy(csi);

    return 0;
}
