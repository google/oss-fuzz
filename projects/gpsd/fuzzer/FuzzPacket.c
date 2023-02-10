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

#include "gpsd_config.h"  /* must be before all includes */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "gpsd.h"

#define kMinInputLength 10
#define kMaxInputLength 9216

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{//gpsd/tests//test_packet.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    {
        struct gps_lexer_t lexer;

        lexer_init(&lexer);
        lexer.errout.debug = 0;

        memcpy(lexer.inbufptr = lexer.inbuffer, Data, Size);
        lexer.inbuflen = Size;

        packet_parse(&lexer);
    }
    {
        struct gps_lexer_t lexer;
        int nullfd = open("/dev/null", O_RDONLY);
        ssize_t st;

        lexer_init(&lexer);
        lexer.errout.debug = 0;

        memcpy(lexer.inbufptr = lexer.inbuffer, Data, Size);
        lexer.inbuflen = Size;

        do {
            st = packet_get(nullfd, &lexer);
        } while (st > 0);

        close(nullfd);
    }

    return 0;
}
