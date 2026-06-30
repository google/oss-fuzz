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

    uint8_t completion_code = payload[sizeof(struct nsm_msg_hdr) + 1];
    if (completion_code == NSM_SUCCESS || completion_code == NSM_ACCEPTED) {
        if (payload_len >= sizeof(struct nsm_msg_hdr) + sizeof(struct nsm_get_histogram_format_resp)) {
            const struct nsm_get_histogram_format_resp* resp = reinterpret_cast<const struct nsm_get_histogram_format_resp*>(payload + sizeof(struct nsm_msg_hdr));
            uint16_t num_of_buckets = le16toh(resp->metadata.num_of_buckets);
            uint8_t type = resp->metadata.bucket_data_type;
            size_t elem_size = 1;
            switch(type) {
                case 0: case 1: elem_size = 1; break;
                case 2: case 3: elem_size = 2; break;
                case 4: case 5: elem_size = 4; break;
                case 6: case 7: elem_size = 8; break;
                case 8: elem_size = 4; break; // NvS24_8 is float (4 bytes)
                default: elem_size = 1; break;
            }
            size_t header_size = sizeof(struct nsm_msg_hdr) + offsetof(struct nsm_get_histogram_format_resp, bucket_offsets);
            if (payload_len < header_size || (size_t)num_of_buckets * elem_size > payload_len - header_size) {
                return 0;
            }
        }
    }

    std::vector<uint8_t> out_buf(65536, 0);
    uint8_t fuzz_cc = 0;
    uint16_t fuzz_reason_code = 0;
    std::vector<uint8_t> fuzz_data_size_buf(65536, 0);
    uint16_t* fuzz_data_size = reinterpret_cast<uint16_t*>(fuzz_data_size_buf.data());
    std::vector<uint8_t> fuzz_meta_data_buf(65536, 0);
    struct nsm_histogram_format_metadata* fuzz_meta_data = reinterpret_cast<struct nsm_histogram_format_metadata*>(fuzz_meta_data_buf.data());
    std::vector<uint8_t> fuzz_bucket_offsets_size_buf(65536, 0);
    uint32_t* fuzz_bucket_offsets_size = reinterpret_cast<uint32_t*>(fuzz_bucket_offsets_size_buf.data());
    decode_get_histogram_format_resp(msg, payload_len, &fuzz_cc, &fuzz_reason_code, fuzz_data_size, fuzz_meta_data, out_buf.data(), fuzz_bucket_offsets_size);

    return 0;
}
