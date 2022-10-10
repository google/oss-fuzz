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

#define kMinInputLength 10
#define kMaxInputLength 1024

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{//src/kdc/t_ndr.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    krb5_data data_in;
    krb5_error_code ret;
    krb5_ticket *ticket;
    krb5_context context;

    data_in = make_data((void *)Data, Size);

    krb5_init_context(&context);
    ret = krb5_decode_ticket(&data_in, &ticket);
    krb5_free_ticket(context, ticket);
    krb5_free_context(context);

    return ret;
}
