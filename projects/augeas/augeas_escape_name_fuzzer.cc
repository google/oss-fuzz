/*
# Copyright 2016 Google Inc.
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

#include <string>

#include <augeas.h>

int escape_match(const uint8_t *data, size_t size){
    augeas *aug = aug_init(NULL, NULL, AUG_NONE);
    std::string data_string(reinterpret_cast<const char*>(data), size);
    char *out = NULL;
    aug_escape_name(aug, data_string.c_str(), &out);
    if (out != NULL){
        aug_match(aug, out, NULL);
    }
    else{
        aug_match(aug, data_string.c_str(), NULL);
    }
    aug_close(aug);
    free(out);
    return 0;
}

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    escape_match(Data, Size);
    return 0;
}
