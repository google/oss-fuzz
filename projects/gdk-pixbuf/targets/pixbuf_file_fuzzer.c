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
    GdkPixbuf *pixbuf;
    GError *error = NULL;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    pixbuf = gdk_pixbuf_new_from_file(tmpfile, &error);
    if (error != NULL) {
        g_clear_error(&error);
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    char *buf = (char *) calloc(size + 1, sizeof(char));
    memcpy(buf, data, size);
    buf[size] = '\0';

    gdk_pixbuf_get_width(pixbuf);
    gdk_pixbuf_get_height(pixbuf);
    gdk_pixbuf_get_bits_per_sample(pixbuf);
    gdk_pixbuf_scale(pixbuf, pixbuf,
            0, 0, 
            gdk_pixbuf_get_width(pixbuf) / 4, 
            gdk_pixbuf_get_height(pixbuf) / 4,
            0, 0, 0.5, 0.5,
            GDK_INTERP_NEAREST);
    unsigned int rot_amount = ((unsigned int) data[0]) % 4;
    pixbuf = gdk_pixbuf_rotate_simple(pixbuf, rot_amount * 90);
    gdk_pixbuf_set_option(pixbuf, buf, buf);
    gdk_pixbuf_get_option(pixbuf, buf);

    free(buf);
    g_clear_object(&pixbuf);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
