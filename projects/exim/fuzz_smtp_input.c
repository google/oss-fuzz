// Copyright 2026 Google LLC.
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

/* Fuzz harness for Exim SMTP input parsing and header processing */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Forward declarations for Exim internal functions */
extern void mime_decode_header(unsigned char *string, size_t len);
extern int parse_extract_address(unsigned char *input, unsigned char **error,
                                  int *start, int *end, int *domain,
                                  int allow_brackets);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 65536) return 0;

    unsigned char *input = (unsigned char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    /* Try to parse as an RFC 5321 address */
    unsigned char *error_msg = NULL;
    int start = 0, end = 0, domain = 0;
    parse_extract_address(input, &error_msg, &start, &end, &domain, 0);

    free(input);
    return 0;
}
