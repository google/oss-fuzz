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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" {
#include "base.h"
#include "device-capability-discovery.h"
}

#include "fuzzer_helpers.h"

namespace {
// Reusable 128 KiB scratch buffers for decoder output parameters (exceeds max
// uint16_t NSM payload length while keeping msg_buf heap-exact for ASan).
alignas(64) uint8_t g_scratch[16][131072];
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) {
        return 0;
    }

    switch (data[0] % 11) {
        case 0: {  // decode_nsm_get_event_source_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_nsm_get_event_source_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 1: {  // decode_nsm_get_event_source_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<bitfield8_t*>(g_scratch[2]);
            decode_nsm_get_event_source_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 2: {  // decode_nsm_set_current_event_sources_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<bitfield8_t*>(g_scratch[1]);
            decode_nsm_set_current_event_sources_req(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 3: {  // decode_nsm_get_event_log_record_v2_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint16_t*>(g_scratch[2]);
            decode_nsm_get_event_log_record_v2_req(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 4: {  // decode_nsm_get_event_log_record_v2_resp_first_handle
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<struct nsm_event_log_record_v2_first_fields*>(g_scratch[1]);
            decode_nsm_get_event_log_record_v2_resp_first_handle(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 5: {  // decode_nsm_get_event_log_record_v2_resp_next_handle
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<struct nsm_event_log_record_v2_next_fields*>(g_scratch[1]);
            decode_nsm_get_event_log_record_v2_resp_next_handle(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 6: {  // decode_nsm_configure_event_acknowledgement_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            bitfield8_t* out_1 = nullptr;
            decode_nsm_configure_event_acknowledgement_req(msg, msg_buf.size(), out_0, &out_1);
            break;
        }
        case 7: {  // decode_nsm_configure_event_acknowledgement_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            bitfield8_t* out_1 = nullptr;
            decode_nsm_configure_event_acknowledgement_resp(msg, msg_buf.size(), out_0, &out_1);
            break;
        }
        case 8: {  // decode_nsm_get_device_capabilities_v2_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_nsm_get_device_capabilities_v2_req(msg, msg_buf.size());
            break;
        }
        case 9: {  // decode_nsm_get_device_capabilities_v2_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint8_t*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            decode_nsm_get_device_capabilities_v2_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 10: {  // decode_nsm_gpio_state_change_event
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            struct nsm_gpio_state_change_event_payload* out_2 = nullptr;
            decode_nsm_gpio_state_change_event(msg, msg_buf.size(), out_0, out_1, &out_2);
            break;
        }
    }

    return 0;
}
