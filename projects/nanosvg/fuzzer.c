/* Copyright 2024 Google LLC
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
// Heuristic: FuzzerGenHeuristic4 :: Target: nsvgParse
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nanosvgrast.h"
#include "nanosvg.h"
#include "stb_image_write.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure null-terminated string
    char* data_copy = (char*)malloc(size + 1);
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Dummy arguments
    const char* dummy_filename = "dummy.svg";
    float dummy_value = 1.0f;

    // Call the target function
    NSVGimage* result = nsvgParse(data_copy, dummy_filename, dummy_value);

    // Free memory
    if (result) {
        nsvgDelete(result);
    }
    free(data_copy);

    return 0;
}
