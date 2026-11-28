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
 * Fuzz target: mobi_parse_rawml
 *
 * Runs the full two-phase pipeline: mobi_load_file followed by
 * mobi_parse_rawml. The second phase covers HTML reconstruction,
 * CSS parsing, OPF generation, and resource extraction — all of
 * which operate on attacker-controlled record data loaded in phase 1.
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

    MOBI_RET ret = mobi_load_file(m, f);
    fclose(f);

    if (ret != MOBI_SUCCESS) {
        mobi_free(m);
        return 0;
    }

    MOBIRawml *rawml = mobi_init_rawml(m);
    if (!rawml) {
        mobi_free(m);
        return 0;
    }

    mobi_parse_rawml(rawml, m);

    mobi_free_rawml(rawml);
    mobi_free(m);
    return 0;
}
