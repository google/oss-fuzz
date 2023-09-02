/* Copyright 2021 Google LLC
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
#include <string.h>
#include "os_regex.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 25) {
        return 0;
    }
    // Regex pattern
    char *pattern = (char *)malloc(24);
    if (pattern == NULL){
        return 0;
    }
    memcpy(pattern, data, 23);
    pattern[23] = '\0';

    data += 23;
    size -= 23;

    // text patterns
    char *str = (char *)malloc(size+1);
    if (str == NULL){
        free(pattern);
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    OSRegex reg;
    if( OSRegex_Compile(pattern, &reg, OS_RETURN_SUBSTRING)) {
        if(OSRegex_Execute(str, &reg)) {
            OSRegex_FreeSubStrings(&reg);
        }
        OSRegex_FreePattern(&reg);
    }

    free(pattern);
    free(str);
    return 0;
}

