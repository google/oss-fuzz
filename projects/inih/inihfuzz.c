// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ini.h"

#define kMinInputLength 8
#define kMaxInputLength 512

int User;
char Prev_section[50];

int dumper(void* user, const char* section, const char* name,
           const char* value)
{
    User = *((int*)user);
    if (strcmp(section, Prev_section)) {
        strncpy(Prev_section, section, sizeof(Prev_section));
        Prev_section[sizeof(Prev_section) - 1] = '\0';
    }
    return 1;
}

extern int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    char *data_in;
    static int u = 100;

    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    Prev_section[0] = '\0';

    data_in = calloc((size + 1), sizeof(char));
    if (!data_in) return 0;

    memcpy(data_in, data, size);

    ini_parse_string(data_in, dumper, &u);

    free(data_in);

    return 0;
}
