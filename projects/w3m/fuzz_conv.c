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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "wc.h"

char *get_null_terminated(const uint8_t *data, size_t size) {
    char *new_str = (char *)malloc(size+1);
    if (new_str == NULL){
            return NULL;
    }
    memcpy(new_str, data, size);
    new_str[size] = '\0';
    return new_str;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    if (size < 30) {
        return 0;
    }

    char *new_str1 = get_null_terminated(data, 20);
    data += 20; size -= 20;

    char *new_str2 = get_null_terminated(data, size);
    //data += 10; size -= 10;

    wc_ces old, from, to;
    from = wc_guess_charset_short(new_str1,0);
    to = wc_guess_charset_short(new_str2, 0);

    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
            return 0;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);

    FILE *f = fopen(filename, "r");
    Str s = Strfgetall(f);
    wc_Str_conv_with_detect(s, &from, from, to);
    if (s != NULL) {
            Strfree(s);
    }

    unlink(filename);

    free(new_str1);
    free(new_str2);
    return 0;
}
