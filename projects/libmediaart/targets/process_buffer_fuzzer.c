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

#include <libmediaart/mediaart.h>

#include "fuzzer_temp_file.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    GFile *file;
    MediaArtProcess *process;
    GCancellable *cancellable;
    GError *error = NULL;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    file = g_file_new_for_path(tmpfile);
    process = media_art_process_new(&error);
    if (error != NULL) {
        g_clear_error(&error);
        g_object_unref(file);
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    char *buf = (char *) calloc(size + 1, sizeof(char));
    memcpy(buf, data, size);
    buf[size] = '\0';

    cancellable = g_cancellable_new();
    media_art_process_buffer(process, MEDIA_ART_ALBUM,
            MEDIA_ART_PROCESS_FLAGS_FORCE, file, buf, size, NULL,
            buf, buf, cancellable, &error);

    free(buf);
    g_clear_error(&error);
    g_object_unref(cancellable);
    g_object_unref(process);
    g_object_unref(file);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
