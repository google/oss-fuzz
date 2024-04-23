// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string>
#include <cstring>
#include <cstdlib>
#include "tiny-json/tiny-json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char* data_str = static_cast<char*>(malloc(size + 1));
    if (data_str == nullptr) {
        return -1;
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';

    enum { MAX_FIELDS = 4 };
    json_t *pool = new json_t[MAX_FIELDS];

    char str[] = "{ \"name\": \"peter\", \"age\": 32 }";	

    json_t const* parent = json_create( str, pool, MAX_FIELDS );
    json_t const* namefield = json_getProperty( parent, data_str );

    free(data_str);
    delete[] pool;

    return 0;
}