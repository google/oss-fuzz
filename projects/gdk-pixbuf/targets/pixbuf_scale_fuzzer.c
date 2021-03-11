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

#include <stdint.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include "fuzzer_temp_file.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    GError *error = NULL;
    GdkPixbuf *pixbuf;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    pixbuf = gdk_pixbuf_new_from_file_at_scale(tmpfile, 1, size, TRUE, &error);
    g_clear_error(&error);
    pixbuf = gdk_pixbuf_new_from_file_at_scale(tmpfile, 1, size, FALSE, &error);
    if (pixbuf != NULL) {
        g_clear_object(&pixbuf);
    } else {
        g_clear_error(&error);
    }
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
