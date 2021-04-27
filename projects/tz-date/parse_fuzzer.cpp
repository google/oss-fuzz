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
#include <string>
#include <iostream>
#include <sstream>
#include "date.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    char *payload = (char *)malloc(size+1);
    if (payload == NULL){
        return 0;
    }
    memcpy(payload, data, size);
    payload[size] = '\0';

    std::istringstream in{payload};
    date::sys_days tp;
    in >> date::parse("%a %F", tp);

    free(payload);
    return 0;
}
