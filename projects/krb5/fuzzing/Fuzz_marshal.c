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

#include "cc-int.h"

#define kMinInputLength 10
#define kMaxInputLength 5120

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{//src/lib/krb5/ccache/t_marshal.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    int MaxVersion = 4;
    krb5_data ser_data;
    krb5_context context;
    krb5_principal princ;
    krb5_creds cred, *alloc_cred;

    krb5_init_context(&context);

    {   //public functions for unmarshalling
        ser_data = make_data((void *)Data, Size);
        krb5_unmarshal_credentials(context, &ser_data, &alloc_cred);
        krb5_free_creds(context, alloc_cred);
    }

    for (size_t version = 1; version <= MaxVersion; version++){

        {   //principal unmarshalling
            k5_unmarshal_princ(Data, Size, version, &princ);
            krb5_free_principal(context, princ);
        }

        {   //cred unmarshalling
            k5_unmarshal_cred(Data, Size, version,&cred);
            krb5_free_cred_contents(context, &cred);
        }
    }

    krb5_free_context(context);
    return 0;
}
