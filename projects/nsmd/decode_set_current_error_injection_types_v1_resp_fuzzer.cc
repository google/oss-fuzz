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

#include <stdint.h>
#include <stddef.h>
#include <vector>

extern "C" {
#include "base.h"
#include "diagnostics.h"
#include "debug-token.h"
#include "device-capability-discovery.h"
#include "device-configuration.h"
#include "firmware-utils.h"
#include "platform-environmental.h"
#include "network-ports.h"
#include "pci-links.h"
}

#include "fuzzer_helpers.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;

    const uint8_t* payload = data;
    size_t payload_len = size;

    if (!validate_nsm_msg_length(payload, payload_len)) {
        return 0;
    }

    const struct nsm_msg* msg = reinterpret_cast<const struct nsm_msg*>(payload);
    const struct nsm_msg_hdr* hdr = reinterpret_cast<const struct nsm_msg_hdr*>(payload);

    // Mismatch prevention: verify request/response type
    if (hdr->request != false) {
        return 0;
    }

    std::vector<uint8_t> out_buf(65536, 0);
    uint8_t fuzz_cc = 0;
    uint16_t fuzz_reason_code = 0;
    decode_set_current_error_injection_types_v1_resp(msg, payload_len, &fuzz_cc, &fuzz_reason_code);

    return 0;
}
