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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "llhttp.h"


int handle_on_message_complete(llhttp_t* arg) {
	return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    llhttp_t parser;
    llhttp_settings_t settings;
    llhttp_type_t http_type;

    /* We need four bytes to determine variable parameters */
    if (size < 4) {
        return 0;
    }

    int headers = (data[0] & 0x01) == 1;
    int chunked_length = (data[1] & 0x01) == 1;
    int keep_alive = (data[2] & 0x01) == 1;
    if (data[0] % 3 == 0) {
        http_type = HTTP_BOTH;
    } 
    else if (data[0] % 3 == 1) {
        http_type = HTTP_REQUEST;
    }
    else {
        http_type = HTTP_RESPONSE;
    }
    data += 4; size -= 4;

	/* Initialize user callbacks and settings */
	llhttp_settings_init(&settings);

	/* Set user callback */
	settings.on_message_complete = handle_on_message_complete;

	llhttp_init(&parser, http_type, &settings);
    llhttp_set_lenient_headers(&parser, headers);
    llhttp_set_lenient_chunked_length(&parser, chunked_length);
    llhttp_set_lenient_keep_alive(&parser, keep_alive);

	llhttp_execute(&parser, data, size);

	return 0;
}
