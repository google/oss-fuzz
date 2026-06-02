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

/* Fuzzer for Redis RESP3 protocol parser */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* Redis resp_parser.h forward declarations */
#include "src/resp_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    RespReq req;
    int nread = 0;
    
    if (size == 0) return 0;
    
    /* Feed data into the RESP parser */
    reqResetClient(&req);
    processInlineBuffer(&req, (char *)data, size, &nread);
    
    return 0;
}
