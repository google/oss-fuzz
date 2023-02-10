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
#include "HTTP.h"
#include "HttpCompat.h"

#define kMinInputLength 5
#define kMaxInputLength 1024

extern int cmd_disable_pfreelist;

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*trafficserver/proxy/hdrs/unit_tests/test_Hdrs.cc*/

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    http_init();
    cmd_disable_pfreelist = true;

    int err = 0;
    const char *start;
    const char *end;
    HTTPHdr hdr;
    HTTPParser parser;

    http_parser_init(&parser);

    start = (char *)Data;
    end   = start + Size;

    {
        hdr.create(HTTP_TYPE_REQUEST);
        err += hdr.parse_req(&parser, &start, end, true);
        http_parser_clear(&parser);
        hdr.destroy();
    }

    {
        hdr.create(HTTP_TYPE_RESPONSE);
        err += hdr.parse_resp(&parser, &start, end, true);
        http_parser_clear(&parser);
        hdr.destroy();
    }

    {
        hdr.create(HTTP_TYPE_REQUEST,HTTP_2_0);
        err += hdr.parse_req(&parser, &start, end, true);
        http_parser_clear(&parser);
        hdr.destroy();
    }

    return err;
}
