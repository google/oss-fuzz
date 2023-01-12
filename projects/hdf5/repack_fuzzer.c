/*
# Copyright 2023 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "h5tools.h"
#include "h5tools_utils.h"
#include "h5repack.h"

#define PROGRAMNAME "h5repack"

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    char *payload = (char *)malloc(size+1);
    if (payload == NULL){
            return 0;
    }
    memcpy(payload, data, size);
    payload[size] = '\0';
    
    pack_opt_t pack_options;
    HDmemset(&pack_options, 0, sizeof(pack_opt_t));

    h5tools_init();
    h5tools_setprogname(PROGRAMNAME);
    if (h5repack_init(&pack_options, 0, FALSE) < 0) {
        h5tools_close();
        return 1;
    }
    
    if (h5repack_addfilter(payload, &pack_options) < 0) {
        h5repack_end(&pack_options);
        h5tools_close();
        return 1;
    }

    
    h5repack_end(&pack_options);
    free(payload);
    h5tools_close();
    return 0;
}

