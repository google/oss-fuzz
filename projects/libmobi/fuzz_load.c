/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Fuzz target: mobi_load_file
 *
 * Feeds arbitrary bytes into libmobi's top-level MOBI loader.
 * Covers PalmDB header parsing, record list parsing, MOBI/EXTH
 * header parsing, and all internal read_* routines triggered on load.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "mobi.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FILE *f = tmpfile();
    if (!f) {
        return 0;
    }
    if (fwrite(data, 1, size, f) != size) {
        fclose(f);
        return 0;
    }
    rewind(f);

    MOBIData *m = mobi_init();
    if (!m) {
        fclose(f);
        return 0;
    }

    mobi_load_file(m, f);

    mobi_free(m);
    fclose(f);
    return 0;
}
