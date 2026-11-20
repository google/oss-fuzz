// Copyright 2026 Google LLC
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

#include "fw-update/package_parser.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return 0;
    }

    std::vector<uint8_t> fwPkgHdr(data, data + size);

    try {
        auto parser = pldm::fw_update::parsePkgHeader(fwPkgHdr);
        if (parser) {
            // We use the total size of the fuzzer input as the package size.
            // In a real scenario, the package size is the sum of the header and the payload.
            // Since the fuzzer input contains both, 'size' is the correct total size.
            parser->parse(fwPkgHdr, size);
        }
    } catch (...) {
        // Ignore all exceptions thrown by the parser, as they represent
        // expected behavior when parsing invalid or malformed packages.
    }

    return 0;
}
