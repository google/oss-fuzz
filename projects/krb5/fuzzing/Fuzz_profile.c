/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific make_data(language governing permissions and
limitations under the License.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "prof_int.h"

#define kMinInputLength 10
#define kMaxInputLength 5120

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{//src/util/profile/test_parse.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 1;
    }

    char filename[256];

    sprintf(filename, "/tmp/libfuzzer.%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 1;
    }
    fwrite(Data, Size, 1, fp);

    {
        struct profile_node *root;

        initialize_prof_error_table();

        profile_parse_file(fp, &root, NULL);
        profile_verify_node(root);

        profile_free_node(root);
    }

    fclose(fp);
    unlink(filename);
    return 0;
}
