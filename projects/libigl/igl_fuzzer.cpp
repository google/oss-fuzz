/*  Copyright 2021 Google LLC
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
#include <igl/MshLoader.h>
#include <iostream>

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    char *nullt_string = (char *)malloc(size+1);
    if (nullt_string == NULL){
            return 0;
    }
    memcpy(nullt_string, data, size);
    nullt_string[size] = '\0';
    std::ofstream fuzz_file;
    fuzz_file.open ("fuzz_file.msh");
    fuzz_file << nullt_string;
    fuzz_file.close();
    try {
    	igl::MshLoader msh_loader("fuzz_file.msh");
    } catch (...) {}
    free(nullt_string);
    return 0;
}

