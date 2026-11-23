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
#include "base.h"
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

    switch (data[0] % 7) {
        case 0: {  // decode_get_supported_nvidia_message_types_resp
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
            decode_get_supported_nvidia_message_types_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 1: {  // decode_get_supported_command_codes_resp
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
            decode_get_supported_command_codes_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 2: {  // decode_common_req_v2
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_common_req_v2(msg, msg_buf.size());
            break;
        }
        case 3: {  // decode_get_gpio_state_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint16_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_get_gpio_state_req(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 4: {  // decode_get_gpio_state_resp
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
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint16_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint8_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<uint32_t*>(g_scratch[5]);
            decode_get_gpio_state_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
        case 5: {  // decode_set_gpio_state_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint16_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint8_t*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            decode_set_gpio_state_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 6: {  // decode_set_gpio_state_resp
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
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint16_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint8_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<uint32_t*>(g_scratch[5]);
            decode_set_gpio_state_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
    }

    return 0;
}
