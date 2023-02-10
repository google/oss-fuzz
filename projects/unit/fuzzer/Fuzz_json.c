/* Copyright 2022 Google LLC
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
#include <nxt_main.h>
#include <nxt_conf.h>

#define kMinInputLength 2
#define kMaxInputLength 5120

static int DoInit = 0;

extern char  **environ;

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{//src/test/nxt_clone_test.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    if(!DoInit){
        nxt_lib_start("tests", NULL, &environ);
        DoInit = 1;
    }

    nxt_mp_t                *mp;
    nxt_str_t               map_str;

    mp = nxt_mp_create(1024, 128, 256, 32);

    map_str.length = Size;
    map_str.start = (uint8_t *) Data;

    nxt_conf_json_parse_str(mp,&map_str);

    nxt_mp_destroy(mp);

    return 0;
}
