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
#include "diagnostics.h"
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

    switch (data[0] % 33) {
        case 0: {  // decode_get_device_diagnostics_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_device_diagnostics_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 1: {  // decode_get_device_diagnostics_resp
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
            auto* out_3 = reinterpret_cast<uint16_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint8_t*>(g_scratch[4]);
            decode_get_device_diagnostics_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4);
            break;
        }
        case 2: {  // decode_reset_network_device_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_reset_network_device_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 3: {  // decode_reset_network_device_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_reset_network_device_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 4: {  // decode_device_reset_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint8_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint32_t*>(g_scratch[2]);
            decode_device_reset_req(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 5: {  // decode_device_reset_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_device_reset_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 6: {  // decode_selective_data_wipe_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint16_t*>(g_scratch[0]);
            decode_selective_data_wipe_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 7: {  // decode_selective_data_wipe_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_selective_data_wipe_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 8: {  // decode_enable_disable_wp_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<enum diagnostics_enable_disable_wp_data_index*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint8_t*>(g_scratch[1]);
            decode_enable_disable_wp_req(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 9: {  // decode_enable_disable_wp_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_enable_disable_wp_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 10: {  // decode_get_network_device_debug_info_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint32_t*>(g_scratch[1]);
            decode_get_network_device_debug_info_req(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 11: {  // decode_get_network_device_debug_info_resp
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
            auto* out_3 = reinterpret_cast<uint8_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint32_t*>(g_scratch[4]);
            decode_get_network_device_debug_info_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4);
            break;
        }
        case 12: {  // decode_erase_trace_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_erase_trace_req(msg, msg_buf.size());
            break;
        }
        case 13: {  // decode_erase_trace_resp
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
            decode_erase_trace_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 14: {  // decode_get_network_device_log_info_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint32_t*>(g_scratch[0]);
            decode_get_network_device_log_info_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 15: {  // decode_get_network_device_log_info_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint32_t*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<struct nsm_device_log_info_breakdown*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint8_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<uint16_t*>(g_scratch[5]);
            decode_get_network_device_log_info_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
        case 16: {  // decode_erase_debug_info_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_erase_debug_info_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 17: {  // decode_erase_debug_info_resp
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
            decode_erase_debug_info_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 18: {  // decode_reset_enum_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_reset_enum_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 19: {  // decode_reset_count_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint16_t*>(g_scratch[0]);
            decode_reset_count_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 20: {  // decode_reset_count_256data
            if (size < 4) return 0;
            size_t count_len = (static_cast<size_t>(data[1]) | (static_cast<size_t>(data[2]) << 8)) % 4097;
            std::vector<uint8_t> buf(data + 3, data + size);
            memset(g_scratch[0], 0, 256);
            decode_reset_count_256data(
                buf.data(), buf.size(),
                reinterpret_cast<uint64_t*>(g_scratch[0]), count_len);
            break;
        }
        case 21: {  // decode_get_device_reset_statistics_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_device_reset_statistics_req(msg, msg_buf.size());
            break;
        }
        case 22: {  // decode_get_device_debug_parameters_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<struct nsm_debug_parameter_id*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<nsm_debug_parameter_sub_id_bitfield*>(g_scratch[2]);
            decode_get_device_debug_parameters_req(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 23: {  // decode_get_device_debug_parameters_resp
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
            decode_get_device_debug_parameters_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 24: {  // decode_set_device_debug_parameters_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<struct nsm_debug_parameter_id*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<nsm_debug_parameter_sub_id_bitfield*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint8_t*>(g_scratch[3]);
            uint8_t* out_4 = nullptr;
            decode_set_device_debug_parameters_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3, &out_4);
            break;
        }
        case 25: {  // decode_set_device_debug_parameters_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_set_device_debug_parameters_resp(msg, msg_buf.size(), out_0);
            break;
        }
        case 26: {  // decode_nsm_diag_get_system_config_event
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
            decode_nsm_diag_get_system_config_event(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 27: {  // decode_nsm_diag_get_tid_config_event
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
            decode_nsm_diag_get_tid_config_event(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 28: {  // decode_nsm_diag_set_test_result_event
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
            auto* out_3 = reinterpret_cast<uint16_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint8_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<uint8_t*>(g_scratch[5]);
            decode_nsm_diag_set_test_result_event(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
        case 29: {  // decode_nsm_diag_set_flow_control_event
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
            decode_nsm_diag_set_flow_control_event(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 30: {  // decode_nsm_diag_set_system_config_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint8_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint8_t*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint8_t*>(g_scratch[3]);
            decode_nsm_diag_set_system_config_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 31: {  // decode_nsm_diag_set_tid_config_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint8_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint16_t*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint8_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint8_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<uint8_t*>(g_scratch[5]);
            decode_nsm_diag_set_tid_config_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
        case 32: {  // decode_nsm_runtime_ist_complete_event
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_runtime_ist_complete_event_payload*>(g_scratch[2]);
            decode_nsm_runtime_ist_complete_event(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
    }

    return 0;
}
