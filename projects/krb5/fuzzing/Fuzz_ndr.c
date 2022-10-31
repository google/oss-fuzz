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

#include "k5-int.h"
#include "kdc_util.h"

#define kMinInputLength 10
#define kMaxInputLength 1024

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{//src/kdc/t_ndr.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    krb5_data data_in;
    krb5_error_code ret;
    struct pac_s4u_delegation_info *di = NULL;

    data_in = make_data((void *)Data, Size);
    ret = ndr_dec_delegation_info(&data_in, &di);
    ndr_free_delegation_info(di);

    return ret;
}
