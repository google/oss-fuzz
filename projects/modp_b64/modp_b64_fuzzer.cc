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
#include <cstddef>
#include <cstdint>
#include "modp_b64.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Skip this iteration if not enough data
    if (size < 2) {
        return 0;
    }

    // Initialise buffer, input and choice
    int choice = data[0] % 3;
    std::string buffer;
    buffer.resize(modp_b64_encode_len(size));
    std::string input(reinterpret_cast<const char*>(data), size);

    // Randomly fuzz encode, decode or round trip functions
    switch (choice) {
        case 0: {
            modp_b64_encode(&buffer[0], input.c_str(), size);
            break;
        }
        case 1: {
            buffer.resize(modp_b64_decode_len(size));
            modp_b64_decode(&buffer[0], input.c_str(), size);
            break;
        }
        case 2: {
            modp_b64_encode(input);
            modp_b64_decode(input);
            break;
        }
        default:
            break;
    }

    // Clean up memory
    buffer.clear();
    input.clear();

    return 0;
}

