/* Copyright 2023 Google LLC
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
#include "zbxeval.h"

#define kMinInputLength 10
#define kMaxInputLength 1024

const char	title_message[] = "fuzz_title_message";
const char	*usage_message[] = {"fuzz_usage_message", NULL};
const char	*help_message[] = {"fuzz_help_message", NULL};
const char	*progname = "fuzz_progname";
const char	syslog_app_name[] = "fuzz_syslog_app_name";

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 1;
    }

    char *data = calloc((Size+1), sizeof(char));  
    memcpy(data, Data, Size);


    {
        zbx_item_query_t    query;
        size_t len =zbx_eval_parse_query(data, Size, &query);

        if(len != 0){
            zbx_eval_clear_query(&query);
        }
    }

    {
	    zbx_eval_context_t  ctx;
        zbx_eval_deserialize(&ctx, NULL, 0, (uint8_t *)data);
        zbx_eval_clear(&ctx);
    }

    {
        char *error = NULL;
        zbx_variant_t value;
        zbx_eval_context_t ctx;

        zbx_timespec_t ts;
        ts.sec = 1;
        ts.ns  = 0;

        int ret = zbx_eval_parse_expression(&ctx, data, 0, &error);
        if(ret == SUCCEED){
            zbx_eval_execute(&ctx, &ts, &value, &error);
        }

        zbx_free(error);
	    zbx_eval_clear(&ctx);
    }

    free(data);

    return 0;
}

