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
//
////////////////////////////////////////////////////////////////////////////////
#include <iostream>
#include "../CJsonObject.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string jsonContent(reinterpret_cast<const char*>(data), size);
    neb::CJsonObject jsonObj;
    if (!jsonObj.Parse(jsonContent)) {
        return 0;
    }
    std::cout << "Parsed JSON content:\n" << jsonObj.ToString() << std::endl;

    return 0;
}
