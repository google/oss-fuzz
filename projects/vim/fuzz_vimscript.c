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
 *
 * OSS-Fuzz harness for Vim's ex command / Vimscript parser.
 * Feeds arbitrary input as ex-mode commands to the Vimscript evaluator.
 *
 * This exercises eval.c, ex_cmds.c, ex_docmd.c, and related paths
 * which have historically been sources of memory corruption CVEs.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char char_u;

/* Minimal interface: parse and evaluate a Vimscript expression */
typedef int typval_T;
int eval0(char_u *arg, typval_T *rettv, char_u **nextcmd, int evalarg);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    typval_T rettv;
    eval0((char_u *)buf, &rettv, NULL, 1);

    free(buf);
    return 0;
}
