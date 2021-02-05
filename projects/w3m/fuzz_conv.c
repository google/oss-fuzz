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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
        if (size < 30) {
                return 0;
        }

        char *new_str = (char *)malloc(10);
        if (new_str == NULL){
                return 0;
        }
        memcpy(new_str, data, 9);
        new_str[9] = '\0';
        data += 10;
        size -= 10;

        char *new_str2 = (char *)malloc(10);
        if (new_str2 == NULL){
                return 0;
        }
        memcpy(new_str2, data, 9);
        new_str2[9] = '\0';
        data += 10;
        size -= 10;

        /* Insert fuzzer contents here */
        wc_ces old, from, to;
        from = wc_guess_charset_short(new_str,0);
        to = wc_guess_charset_short(new_str2, 0);

        char filename[256];
        sprintf(filename, "/tmp/libfuzzer.%d", getpid());

        FILE *fp = fopen(filename, "wb");
        if (!fp)
                return 0;
        fwrite(data, size, 1, fp);
        fclose(fp);

        Str s;// = Strnew();

         FILE *f = fopen(filename, "r");
        s = Strfgetall(f);
        wc_Str_conv_with_detect(s, &from, from, to);
        if (s != NULL) {
                Strfree(s);
        }

        unlink(filename);
        /* - end of fuzzer contents  - */

        free(new_str);
        free(new_str2);
        return 0;
}
