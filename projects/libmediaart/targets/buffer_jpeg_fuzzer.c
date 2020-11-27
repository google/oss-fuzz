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
    if (!(size > 2 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff)) {
        return 0;
    }

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    media_art_buffer_to_jpeg(data, size, "image/jpeg", tmpfile, NULL);

    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
