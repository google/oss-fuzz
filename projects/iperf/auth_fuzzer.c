// Copyright 2025 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// Declaration of the function from iperf_auth.c (it is not static)
int Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Base64Decode expects a null-terminated string.
    char *str = (char *)malloc(size + 1);
    if (!str) {
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    unsigned char *buffer = NULL;
    size_t length = 0;

    // Call the target function
    Base64Decode(str, &buffer, &length);

    if (buffer) {
        free(buffer);
    }
    free(str);
    return 0;
}
