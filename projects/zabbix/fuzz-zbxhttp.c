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
#include "zbxhttp.h"

#define kMinInputLength 10
#define kMaxInputLength 1024

const char	title_message[] = "fuzz_title_message";
const char	*usage_message[] = {"fuzz_usage_message", NULL};
const char	*help_message[] = {"fuzz_help_message", NULL};
const char	*progname = "fuzz_progname";
const char	syslog_app_name[] = "fuzz_syslog_app_name";

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{

    if (Size < kMinInputLength || Size > kMaxInputLength) {
        return 1;
    }

    char *data = calloc((Size+1), sizeof(char));  
    memcpy(data, Data, Size);
  
    char *substitute = NULL;
    zbx_http_url_decode(data, &substitute);

    free(data);
    free(substitute);

    return 0;
}
