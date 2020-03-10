/* Copyright 2020 Google Inc.

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


#include "cxxfilt.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        if (size  < 3)
                return 0;
        char *new_str = malloc(size+1);
        if (new_str == NULL)
                return 0;
        memcpy(new_str, data, size);
        new_str[size] = '\0';
        int flags2 = (int)data[0];

        cplus_demangle_set_style(DMGL_GNU_V3);
        char *new_res = cplus_demangle(new_str, flags2);
        if (new_res)
                free(new_res);

        free(new_str);
        return 0;
}
