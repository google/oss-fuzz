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
#include "platform-environmental.h"
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

    switch (data[0] % 122) {
        case 0: {  // decode_get_leak_detection_info_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_leak_detection_info_req(msg, msg_buf.size());
            break;
        }
        case 1: {  // decode_get_leak_detection_info_resp
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
            auto* out_3 = reinterpret_cast<uint8_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint8_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<size_t*>(g_scratch[5]);
            decode_get_leak_detection_info_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
        case 2: {  // decode_set_leak_detection_thresholds_req
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
            auto* out_3 = reinterpret_cast<size_t*>(g_scratch[3]);
            decode_set_leak_detection_thresholds_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 3: {  // decode_set_leak_detection_thresholds_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_set_leak_detection_thresholds_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 4: {  // decode_send_spi_command_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_send_spi_command_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 5: {  // decode_send_spi_transaction_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_send_spi_transaction_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 6: {  // decode_send_spi_operation_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_send_spi_operation_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 7: {  // decode_read_spi_status_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<enum nsm_spi_status*>(g_scratch[2]);
            decode_read_spi_status_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 8: {  // decode_read_spi_last_block_resp
            if (size < 2 + sizeof(struct nsm_msg_hdr)) return 0;
            uint8_t in_5 = static_cast<uint8_t>(data[1]);
            std::vector<uint8_t> msg_buf(data + 2, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint8_t*>(g_scratch[2]);
            decode_read_spi_last_block_resp(msg, msg_buf.size(), out_0, out_1, out_2, in_5);
            break;
        }
        case 9: {  // decode_read_spi_block_resp
            if (size < 2 + sizeof(struct nsm_msg_hdr)) return 0;
            uint8_t in_5 = static_cast<uint8_t>(data[1]);
            std::vector<uint8_t> msg_buf(data + 2, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint8_t*>(g_scratch[2]);
            decode_read_spi_block_resp(msg, msg_buf.size(), out_0, out_1, out_2, in_5);
            break;
        }
        case 10: {  // decode_get_platform_env_command_no_payload_req
            if (size < 2 + sizeof(struct nsm_msg_hdr)) return 0;
            enum nsm_platform_environmental_commands in_2 = static_cast<enum nsm_platform_environmental_commands>(data[1]);
            std::vector<uint8_t> msg_buf(data + 2, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_platform_env_command_no_payload_req(msg, msg_buf.size(), in_2);
            break;
        }
        case 11: {  // decode_get_driver_info_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_driver_info_req(msg, msg_buf.size());
            break;
        }
        case 12: {  // decode_get_driver_info_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<enum8*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<char*>(g_scratch[3]);
            decode_get_driver_info_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 13: {  // decode_get_inventory_information_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_inventory_information_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 14: {  // decode_get_inventory_information_resp
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
            decode_get_inventory_information_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 15: {  // decode_inventory_information_as_uint32
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + std::min<size_t>(size, 65536));
            decode_inventory_information_as_uint32(
                buf.data(), static_cast<uint16_t>(buf.size()));
            break;
        }
        case 16: {  // decode_get_temperature_reading_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_temperature_reading_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 17: {  // decode_get_temperature_reading_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<double*>(g_scratch[2]);
            decode_get_temperature_reading_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 18: {  // decode_read_thermal_parameter_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_read_thermal_parameter_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 19: {  // decode_read_thermal_parameter_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<int32_t*>(g_scratch[2]);
            decode_read_thermal_parameter_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 20: {  // decode_aggregate_thermal_parameter_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<int32_t*>(g_scratch[0]);
            decode_aggregate_thermal_parameter_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 21: {  // decode_get_current_power_draw_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint8_t*>(g_scratch[1]);
            decode_get_current_power_draw_req(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 22: {  // decode_get_current_power_draw_resp
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
            decode_get_current_power_draw_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 23: {  // decode_aggregate_get_current_power_draw_reading
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint32_t*>(g_scratch[0]);
            decode_aggregate_get_current_power_draw_reading(buf.data(), buf.size(), out_0);
            break;
        }
        case 24: {  // decode_get_max_observed_power_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint8_t*>(g_scratch[1]);
            decode_get_max_observed_power_req(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 25: {  // decode_get_max_observed_power_resp
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
            decode_get_max_observed_power_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 26: {  // decode_get_current_energy_count_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_current_energy_count_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 27: {  // decode_get_current_energy_count_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint64_t*>(g_scratch[2]);
            decode_get_current_energy_count_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 28: {  // decode_get_voltage_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_voltage_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 29: {  // decode_get_voltage_resp
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
            decode_get_voltage_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 30: {  // decode_get_altitude_pressure_resp
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
            decode_get_altitude_pressure_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 31: {  // decode_aggregate_timestamp_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint64_t*>(g_scratch[0]);
            decode_aggregate_timestamp_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 32: {  // decode_aggregate_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<size_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint8_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint16_t*>(g_scratch[2]);
            decode_aggregate_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 33: {  // decode_aggregate_resp_sample
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            size_t consumed_len = 0, data_len = 0;
            uint8_t tag = 0;
            bool valid = false;
            const uint8_t* sample_data = nullptr;
            decode_aggregate_resp_sample(
                reinterpret_cast<const struct nsm_aggregate_resp_sample*>(buf.data()),
                buf.size(), &consumed_len, &tag, &valid, &sample_data, &data_len);
            break;
        }
        case 34: {  // decode_sequence_token_record
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint32_t*>(g_scratch[0]);
            decode_sequence_token_record(buf.data(), buf.size(), out_0);
            break;
        }
        case 35: {  // decode_aggregate_temperature_reading_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<double*>(g_scratch[0]);
            decode_aggregate_temperature_reading_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 36: {  // decode_get_MIG_mode_resp
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
            auto* out_3 = reinterpret_cast<bitfield8_t*>(g_scratch[3]);
            decode_get_MIG_mode_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 37: {  // decode_get_MIG_mode_event_resp
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
            decode_get_MIG_mode_event_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 38: {  // decode_set_MIG_mode_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_set_MIG_mode_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 39: {  // decode_set_MIG_mode_resp
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
            decode_set_MIG_mode_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 40: {  // decode_set_MIG_mode_event_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_set_MIG_mode_event_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 41: {  // decode_get_ECC_mode_resp
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
            auto* out_3 = reinterpret_cast<bitfield8_t*>(g_scratch[3]);
            decode_get_ECC_mode_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 42: {  // decode_get_ECC_mode_event_resp
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
            decode_get_ECC_mode_event_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 43: {  // decode_set_ECC_mode_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_set_ECC_mode_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 44: {  // decode_set_ECC_mode_resp
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
            decode_set_ECC_mode_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 45: {  // decode_set_ECC_mode_event_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_set_ECC_mode_event_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 46: {  // decode_get_ECC_error_counts_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_ECC_error_counts*>(g_scratch[3]);
            decode_get_ECC_error_counts_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 47: {  // decode_aggregate_energy_count_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint64_t*>(g_scratch[0]);
            decode_aggregate_energy_count_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 48: {  // decode_aggregate_voltage_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint32_t*>(g_scratch[0]);
            decode_aggregate_voltage_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 49: {  // decode_set_clock_limit_req
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
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            decode_set_clock_limit_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 50: {  // decode_set_clock_limit_resp
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
            decode_set_clock_limit_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 51: {  // decode_get_programmable_EDPp_scaling_factor_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_EDPp_scaling_factors*>(g_scratch[3]);
            decode_get_programmable_EDPp_scaling_factor_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 52: {  // decode_set_programmable_EDPp_scaling_factor_req
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
            decode_set_programmable_EDPp_scaling_factor_req(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 53: {  // decode_set_programmable_EDPp_scaling_factor_resp
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
            decode_set_programmable_EDPp_scaling_factor_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 54: {  // decode_get_clock_limit_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_clock_limit_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 55: {  // decode_get_clock_limit_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_clock_limit*>(g_scratch[3]);
            decode_get_clock_limit_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 56: {  // decode_get_curr_clock_freq_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_curr_clock_freq_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 57: {  // decode_get_curr_clock_freq_resp
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
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            decode_get_curr_clock_freq_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 58: {  // decode_get_current_clock_event_reason_code_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_current_clock_event_reason_code_req(msg, msg_buf.size());
            break;
        }
        case 59: {  // decode_get_current_clock_event_reason_code_resp
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
            auto* out_3 = reinterpret_cast<bitfield32_t*>(g_scratch[3]);
            decode_get_current_clock_event_reason_code_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 60: {  // decode_get_accum_GPU_util_time_resp
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
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint32_t*>(g_scratch[4]);
            decode_get_accum_GPU_util_time_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4);
            break;
        }
        case 61: {  // decode_get_current_utilization_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_get_current_utilization_data*>(g_scratch[3]);
            decode_get_current_utilization_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 62: {  // decode_get_current_utilization_event_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_get_current_utilization_data*>(g_scratch[2]);
            decode_get_current_utilization_event_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 63: {  // decode_set_power_limit_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint32_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint8_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint8_t*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            decode_set_power_limit_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 64: {  // decode_set_power_limit_resp
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
            decode_set_power_limit_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 65: {  // decode_get_power_limit_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint32_t*>(g_scratch[0]);
            decode_get_power_limit_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 66: {  // decode_get_power_limit_resp
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
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint32_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<uint32_t*>(g_scratch[5]);
            decode_get_power_limit_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
        case 67: {  // decode_get_clock_output_enable_state_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_clock_output_enable_state_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 68: {  // decode_get_clock_output_enable_state_resp
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
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            decode_get_clock_output_enable_state_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 69: {  // decode_get_row_remap_state_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_row_remap_state_req(msg, msg_buf.size());
            break;
        }
        case 70: {  // decode_get_row_remap_state_resp
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
            auto* out_3 = reinterpret_cast<bitfield8_t*>(g_scratch[3]);
            decode_get_row_remap_state_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 71: {  // decode_get_row_remapping_counts_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_row_remapping_counts_req(msg, msg_buf.size());
            break;
        }
        case 72: {  // decode_get_row_remapping_counts_resp
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
            auto* out_3 = reinterpret_cast<uint32_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint32_t*>(g_scratch[4]);
            decode_get_row_remapping_counts_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4);
            break;
        }
        case 73: {  // decode_get_memory_capacity_util_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_memory_capacity_util_req(msg, msg_buf.size());
            break;
        }
        case 74: {  // decode_get_memory_capacity_util_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_memory_capacity_utilization*>(g_scratch[3]);
            decode_get_memory_capacity_util_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 75: {  // decode_get_memory_capacity_util_event_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_memory_capacity_utilization*>(g_scratch[2]);
            decode_get_memory_capacity_util_event_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 76: {  // decode_nsm_xid_event
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_xid_event_payload*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<char*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<size_t*>(g_scratch[4]);
            decode_nsm_xid_event(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4);
            break;
        }
        case 77: {  // decode_nsm_reset_required_event
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_reset_required_event(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 78: {  // decode_get_supported_gpm_metrics_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_get_supported_gpm_metrics_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 79: {  // decode_get_supported_gpm_metrics_resp
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
            auto* out_5 = reinterpret_cast<uint16_t*>(g_scratch[5]);
            decode_get_supported_gpm_metrics_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
        case 80: {  // decode_query_aggregate_gpm_metrics_req
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
            const uint8_t* out_3 = nullptr;
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<size_t*>(g_scratch[4]);
            decode_query_aggregate_gpm_metrics_req(msg, msg_buf.size(), out_0, out_1, out_2, &out_3, out_4);
            break;
        }
        case 81: {  // decode_query_per_instance_gpm_metrics_req
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
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint32_t*>(g_scratch[4]);
            decode_query_per_instance_gpm_metrics_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4);
            break;
        }
        case 82: {  // decode_query_per_instance_gpm_metrics_v2_req
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
            bitfield8_t* out_4 = nullptr;
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<size_t*>(g_scratch[5]);
            decode_query_per_instance_gpm_metrics_v2_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3, &out_4, out_5);
            break;
        }
        case 83: {  // decode_aggregate_gpm_metric_percentage_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<double*>(g_scratch[0]);
            decode_aggregate_gpm_metric_percentage_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 84: {  // decode_aggregate_gpm_metric_bandwidth_data
            if (size < 2) return 0;
            std::vector<uint8_t> buf(data + 1, data + size);
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint64_t*>(g_scratch[0]);
            decode_aggregate_gpm_metric_bandwidth_data(buf.data(), buf.size(), out_0);
            break;
        }
        case 85: {  // decode_get_violation_duration_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_violation_duration_req(msg, msg_buf.size());
            break;
        }
        case 86: {  // decode_get_violation_duration_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_violation_duration*>(g_scratch[3]);
            decode_get_violation_duration_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 87: {  // decode_get_violation_duration_event_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_violation_duration*>(g_scratch[2]);
            decode_get_violation_duration_event_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 88: {  // decode_get_powersmoothing_featinfo_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_powersmoothing_featinfo_req(msg, msg_buf.size());
            break;
        }
        case 89: {  // decode_get_powersmoothing_featinfo_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_pwr_smoothing_featureinfo_data*>(g_scratch[3]);
            decode_get_powersmoothing_featinfo_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 90: {  // decode_get_hardware_lifetime_cricuitry_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_hardware_lifetime_cricuitry_req(msg, msg_buf.size());
            break;
        }
        case 91: {  // decode_get_hardware_lifetime_cricuitry_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_hardwarecircuitry_data*>(g_scratch[3]);
            decode_get_hardware_lifetime_cricuitry_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 92: {  // decode_get_current_profile_info_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_current_profile_info_req(msg, msg_buf.size());
            break;
        }
        case 93: {  // decode_get_current_profile_info_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_get_current_profile_data*>(g_scratch[3]);
            decode_get_current_profile_info_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 94: {  // decode_query_admin_override_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_query_admin_override_req(msg, msg_buf.size());
            break;
        }
        case 95: {  // decode_query_admin_override_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_admin_override_data*>(g_scratch[3]);
            decode_query_admin_override_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 96: {  // decode_set_active_preset_profile_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_set_active_preset_profile_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 97: {  // decode_set_active_preset_profile_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_set_active_preset_profile_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 98: {  // decode_setup_admin_override_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint32_t*>(g_scratch[1]);
            decode_setup_admin_override_req(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 99: {  // decode_setup_admin_override_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_setup_admin_override_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 100: {  // decode_apply_admin_override_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_apply_admin_override_req(msg, msg_buf.size());
            break;
        }
        case 101: {  // decode_apply_admin_override_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_apply_admin_override_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 102: {  // decode_toggle_immediate_rampdown_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_toggle_immediate_rampdown_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 103: {  // decode_toggle_immediate_rampdown_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_toggle_immediate_rampdown_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 104: {  // decode_toggle_feature_state_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            decode_toggle_feature_state_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 105: {  // decode_toggle_feature_state_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_toggle_feature_state_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 106: {  // decode_get_preset_profile_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_preset_profile_req(msg, msg_buf.size());
            break;
        }
        case 107: {  // decode_get_preset_profile_metadata_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_get_all_preset_profile_meta_data*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint8_t*>(g_scratch[3]);
            decode_get_preset_profile_metadata_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 108: {  // decode_get_preset_profile_data_from_resp
            if (size < 3 + sizeof(struct nsm_msg_hdr)) return 0;
            uint8_t in_4 = static_cast<uint8_t>(data[1]);
            uint8_t in_5 = static_cast<uint8_t>(data[2]);
            std::vector<uint8_t> msg_buf(data + 3, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_preset_profile_data*>(g_scratch[2]);
            decode_get_preset_profile_data_from_resp(msg, msg_buf.size(), out_0, out_1, in_4, in_5, out_2);
            break;
        }
        case 109: {  // decode_update_preset_profile_param_req
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
            decode_update_preset_profile_param_req(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 110: {  // decode_update_preset_profile_param_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_update_preset_profile_param_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 111: {  // decode_get_row_remap_availability_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_row_remap_availability_req(msg, msg_buf.size());
            break;
        }
        case 112: {  // decode_get_row_remap_availability_resp
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
            auto* out_3 = reinterpret_cast<struct nsm_row_remap_availability*>(g_scratch[3]);
            decode_get_row_remap_availability_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 113: {  // decode_get_workload_power_profile_info_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint16_t*>(g_scratch[0]);
            decode_get_workload_power_profile_info_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 114: {  // decode_get_workload_power_profile_info_metadata_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_all_workload_power_profile_meta_data*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint8_t*>(g_scratch[3]);
            decode_get_workload_power_profile_info_metadata_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 115: {  // decode_get_workload_power_profile_info_data_resp
            if (size < 3 + sizeof(struct nsm_msg_hdr)) return 0;
            uint8_t in_4 = static_cast<uint8_t>(data[1]);
            uint8_t in_5 = static_cast<uint8_t>(data[2]);
            std::vector<uint8_t> msg_buf(data + 3, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_workload_power_profile_data*>(g_scratch[2]);
            decode_get_workload_power_profile_info_data_resp(msg, msg_buf.size(), out_0, out_1, in_4, in_5, out_2);
            break;
        }
        case 116: {  // decode_get_workload_power_profile_status_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_get_workload_power_profile_status_req(msg, msg_buf.size());
            break;
        }
        case 117: {  // decode_get_workload_power_profile_status_resp
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
            auto* out_3 = reinterpret_cast<struct workload_power_profile_status*>(g_scratch[3]);
            decode_get_workload_power_profile_status_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3);
            break;
        }
        case 118: {  // decode_enable_workload_power_profile_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<bitfield256_t*>(g_scratch[0]);
            decode_enable_workload_power_profile_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 119: {  // decode_enable_workload_power_profile_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_enable_workload_power_profile_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 120: {  // decode_disable_workload_power_profile_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<bitfield256_t*>(g_scratch[0]);
            decode_disable_workload_power_profile_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 121: {  // decode_disable_workload_power_profile_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_disable_workload_power_profile_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
    }

    return 0;
}
