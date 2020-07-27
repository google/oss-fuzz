/* Copyright 2020 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "mountP.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        struct libmnt_table *tb = NULL;
        FILE *f = NULL;

        if (size == 0)
                return 0;

        tb = mnt_new_table();
        assert(tb);

        f = fmemopen((char*) data, size, "re");
        assert(f);

        (void) mnt_table_parse_stream(tb, f, "mountinfo");

        mnt_unref_table(tb);
        fclose(f);

        return 0;
}
