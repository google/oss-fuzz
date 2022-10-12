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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <k5-json.h>

#define kMinInputLength 10
#define kMaxInputLength 1024

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{//src/util/support/t_json.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

//Add Null byte
    uint8_t *DataFx;
    size_t SizeFx = Size+1;
    DataFx = (uint8_t *)calloc(SizeFx,sizeof(uint8_t));
    memcpy((void *)DataFx,(void *)Data,Size);

    k5_json_value v;
    k5_json_decode((char *)DataFx, &v);
    k5_json_release(v);

    free(DataFx);
    return 0;
}
