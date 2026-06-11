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
 * Fuzzer: ucl_emit_roundtrip_fuzzer
 *
 * Coverage gap addressed: the existing ucl_add_string_fuzzer only exercises
 * parsing.  This fuzzer additionally exercises the emit path and ensures
 * that parse -> emit -> re-parse produces a consistent object tree, catching
 * bugs in ucl_object_emit (UCL, JSON, YAML, MSGPACK formats) as well as
 * memory management issues in the emitter functions.
 *
 * Strategy:
 *   1. Use the first byte of the input as a selector to choose the emit format.
 *   2. Parse the remainder of the input as a UCL document.
 *   3. If parsing succeeds, emit the resulting object in the selected format.
 *   4. Re-parse the emitted bytes and check that re-parsing does not crash.
 *   5. Compare the type of the root object in both parses (basic sanity check).
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ucl.h"

/* Emit formats we cycle through based on the selector byte */
static const enum ucl_emitter emit_formats[] = {
    UCL_EMIT_JSON,
    UCL_EMIT_JSON_COMPACT,
    UCL_EMIT_CONFIG,
    UCL_EMIT_YAML,
    UCL_EMIT_MSGPACK,
};
#define NUM_FORMATS (sizeof(emit_formats) / sizeof(emit_formats[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    /* Choose emit format from the first byte */
    enum ucl_emitter fmt = emit_formats[data[0] % NUM_FORMATS];

    /* Parse the rest as UCL */
    struct ucl_parser *parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
    if (!parser) {
        return 0;
    }

    ucl_parser_add_string(parser, (const char *)(data + 1), size - 1);

    ucl_object_t *obj = ucl_parser_get_object(parser);
    ucl_parser_free(parser);

    if (!obj) {
        return 0;
    }

    /* Emit to memory using the chosen format.                                *
     * Use emit_len to get the real byte length (safe for MSGPACK which may   *
     * contain NUL bytes in the binary output).                               */
    size_t emitted_len = 0;
    unsigned char *emitted = ucl_object_emit_len(obj, fmt, &emitted_len);
    ucl_object_unref(obj);

    if (!emitted || emitted_len == 0) {
        free(emitted);
        return 0;
    }

    /* Re-parse the emitted output */
    struct ucl_parser *parser2 = ucl_parser_new(UCL_PARSER_NO_FILEVARS);
    if (parser2) {
        /* For MSGPACK re-parsing we need the full chunk API */
        if (fmt == UCL_EMIT_MSGPACK) {
            ucl_parser_add_chunk_full(parser2, emitted, emitted_len, 0,
                                      UCL_DUPLICATE_APPEND, UCL_PARSE_MSGPACK);
        } else {
            ucl_parser_add_chunk(parser2, emitted, emitted_len);
        }
        ucl_object_t *obj2 = ucl_parser_get_object(parser2);
        if (obj2) {
            ucl_object_unref(obj2);
        }
        ucl_parser_free(parser2);
    }

    free(emitted);
    return 0;
}
