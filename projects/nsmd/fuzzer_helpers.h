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

#pragma once

#include <stdint.h>
#include <stddef.h>

extern "C" {
#include "base.h"
}

// Validates that the packet actually contains the number of bytes specified in the headers
inline bool validate_nsm_msg_length(const uint8_t* payload, size_t payload_len) {
    if (payload_len < sizeof(struct nsm_msg_hdr)) {
        return false;
    }
    const struct nsm_msg_hdr* hdr = reinterpret_cast<const struct nsm_msg_hdr*>(payload);
    
    if (hdr->request) {
        // Request v1
        if (payload_len >= sizeof(struct nsm_msg_hdr) + sizeof(struct nsm_common_req)) {
            const struct nsm_common_req* req = reinterpret_cast<const struct nsm_common_req*>(payload + sizeof(struct nsm_msg_hdr));
            uint32_t data_size = req->data_size;
            if (payload_len >= sizeof(struct nsm_msg_hdr) + sizeof(struct nsm_common_req) + data_size) {
                return true;
            }
        }
        
        // Request v2
        if (payload_len >= sizeof(struct nsm_msg_hdr) + sizeof(struct nsm_common_req_v2)) {
            const struct nsm_common_req_v2* req_v2 = reinterpret_cast<const struct nsm_common_req_v2*>(payload + sizeof(struct nsm_msg_hdr));
            uint32_t data_size_v2 = le16toh(req_v2->data_size);
            if (payload_len >= sizeof(struct nsm_msg_hdr) + sizeof(struct nsm_common_req_v2) + data_size_v2) {
                return true;
            }
        }
        return false;
    } else {
        // Response
        if (payload_len < sizeof(struct nsm_msg_hdr) + 2) { // command + completion_code
            return false;
        }
        uint8_t completion_code = payload[sizeof(struct nsm_msg_hdr) + 1];
        if (completion_code != NSM_SUCCESS && completion_code != NSM_ACCEPTED) {
            // Non-success response
            if (payload_len >= sizeof(struct nsm_msg_hdr) + sizeof(struct nsm_common_non_success_resp)) {
                return true;
            }
            return false;
        }
        
        // Success response
        if (payload_len < sizeof(struct nsm_msg_hdr) + sizeof(struct nsm_common_resp)) {
            return false;
        }
        const struct nsm_common_resp* resp = reinterpret_cast<const struct nsm_common_resp*>(payload + sizeof(struct nsm_msg_hdr));
        uint32_t data_size = le16toh(resp->data_size);
        if (payload_len >= sizeof(struct nsm_msg_hdr) + sizeof(struct nsm_common_resp) + data_size) {
            return true;
        }
        return false;
    }
}
