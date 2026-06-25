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
 * Fuzz target: Huffman decompression via full document load
 *
 * KF8/MOBI documents can use Huffman-CDIC compression.
 * This target feeds arbitrary bytes as a raw MOBI document and lets
 * libmobi decide the compression type from the header. The Huffman
 * path is taken when compression type == 2 in the MOBI header.
 * Seed corpus should include real HuffCDIC-compressed MOBI files.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "mobi.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) {
        return 0;
    }

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

    if (ret == MOBI_SUCCESS) {
        MOBIRawml *rawml = mobi_init_rawml(m);
        if (rawml) {
            mobi_parse_rawml(rawml, m);
            mobi_free_rawml(rawml);
        }
    }

    mobi_free(m);
    return 0;
}
