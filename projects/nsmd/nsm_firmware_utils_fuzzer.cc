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
#include <cstdio>
#include <vector>

extern "C" {
#include "base.h"
#include "firmware-utils.h"
}

#include "fuzzer_helpers.h"

namespace {
// Reusable 128 KiB scratch buffers for decoder output parameters (exceeds max
// uint16_t NSM payload length while keeping msg_buf heap-exact for ASan).
alignas(64) uint8_t g_scratch[16][131072];
}  // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
    // Silence verbose DBGE() hex dumps printed to stdout in firmware-utils.c.
    std::freopen("/dev/null", "w", stdout);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) {
        return 0;
    }

    switch (data[0] % 45) {
        case 0: {  // decode_nsm_firmware_aggregate_tag_uint8
            std::vector<uint8_t> buf(data + 1, data + std::min<size_t>(size, 65536));
            uint8_t dummy = 0;
            uint8_t* cursor = buf.empty() ? &dummy : buf.data();
            uint16_t rem = static_cast<uint16_t>(buf.size());
            uint8_t tag = 0, valid = 0, val = 0;
            decode_nsm_firmware_aggregate_tag_uint8(&cursor, &tag, &valid, &val, &rem);
            break;
        }
        case 1: {  // decode_nsm_firmware_aggregate_tag_uint16
            std::vector<uint8_t> buf(data + 1, data + std::min<size_t>(size, 65536));
            uint8_t dummy = 0;
            uint8_t* cursor = buf.empty() ? &dummy : buf.data();
            uint16_t rem = static_cast<uint16_t>(buf.size());
            uint8_t tag = 0, valid = 0;
            uint16_t val = 0;
            decode_nsm_firmware_aggregate_tag_uint16(&cursor, &tag, &valid, &val, &rem);
            break;
        }
        case 2: {  // decode_nsm_firmware_aggregate_tag_uint32
            std::vector<uint8_t> buf(data + 1, data + std::min<size_t>(size, 65536));
            uint8_t dummy = 0;
            uint8_t* cursor = buf.empty() ? &dummy : buf.data();
            uint16_t rem = static_cast<uint16_t>(buf.size());
            uint8_t tag = 0, valid = 0;
            uint32_t val = 0;
            decode_nsm_firmware_aggregate_tag_uint32(&cursor, &tag, &valid, &val, &rem);
            break;
        }
        case 3: {  // decode_nsm_firmware_aggregate_tag_uint64
            std::vector<uint8_t> buf(data + 1, data + std::min<size_t>(size, 65536));
            uint8_t dummy = 0;
            uint8_t* cursor = buf.empty() ? &dummy : buf.data();
            uint16_t rem = static_cast<uint16_t>(buf.size());
            uint8_t tag = 0, valid = 0;
            uint64_t val = 0;
            decode_nsm_firmware_aggregate_tag_uint64(&cursor, &tag, &valid, &val, &rem);
            break;
        }
        case 4: {  // decode_nsm_firmware_aggregate_tag_uint8_array
            std::vector<uint8_t> buf(data + 1, data + std::min<size_t>(size, 65536));
            uint8_t dummy = 0;
            uint8_t* cursor = buf.empty() ? &dummy : buf.data();
            uint16_t rem = static_cast<uint16_t>(buf.size());
            uint8_t tag = 0, valid = 0;
            memset(g_scratch[0], 0, 256);
            decode_nsm_firmware_aggregate_tag_uint8_array(&cursor, &tag, &valid, g_scratch[0], &rem);
            break;
        }
        case 5: {  // decode_nsm_firmware_aggregate_tag_skip
            std::vector<uint8_t> buf(data + 1, data + std::min<size_t>(size, 65536));
            uint8_t dummy = 0;
            uint8_t* cursor = buf.empty() ? &dummy : buf.data();
            uint16_t rem = static_cast<uint16_t>(buf.size());
            decode_nsm_firmware_aggregate_tag_skip(&cursor, &rem);
            break;
        }
        case 6: {  // decode_nsm_query_get_erot_state_parameters_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_firmware_erot_state_info_req*>(g_scratch[0]);
            decode_nsm_query_get_erot_state_parameters_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 7: {  // decode_nsm_query_get_erot_state_parameters_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            struct nsm_firmware_erot_state_info_resp out_2 = {};
            decode_nsm_query_get_erot_state_parameters_resp(msg, msg_buf.size(), out_0, out_1, &out_2);
            free(out_2.slot_info);
            break;
        }
        case 8: {  // decode_nsm_firmware_irreversible_config_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_firmware_irreversible_config_req*>(g_scratch[0]);
            decode_nsm_firmware_irreversible_config_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 9: {  // decode_nsm_firmware_irreversible_config_request_0_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_firmware_irreversible_config_request_0_resp*>(g_scratch[2]);
            decode_nsm_firmware_irreversible_config_request_0_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 10: {  // decode_nsm_firmware_irreversible_config_request_1_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_firmware_irreversible_config_request_1_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 11: {  // decode_nsm_firmware_irreversible_config_request_2_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_firmware_irreversible_config_request_2_resp*>(g_scratch[2]);
            decode_nsm_firmware_irreversible_config_request_2_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 12: {  // decode_nsm_code_auth_key_perm_query_req
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
            decode_nsm_code_auth_key_perm_query_req(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 13: {  // decode_nsm_code_auth_key_perm_query_resp
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
            auto* out_5 = reinterpret_cast<uint8_t*>(g_scratch[5]);
            memset(g_scratch[6], 0, 256);
            auto* out_6 = reinterpret_cast<uint8_t*>(g_scratch[6]);
            memset(g_scratch[7], 0, 256);
            auto* out_7 = reinterpret_cast<uint8_t*>(g_scratch[7]);
            memset(g_scratch[8], 0, 256);
            auto* out_8 = reinterpret_cast<uint8_t*>(g_scratch[8]);
            decode_nsm_code_auth_key_perm_query_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5, out_6, out_7, out_8);
            break;
        }
        case 14: {  // decode_nsm_code_auth_key_perm_update_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<enum nsm_code_auth_key_perm_request_type*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<uint16_t*>(g_scratch[2]);
            memset(g_scratch[3], 0, 256);
            auto* out_3 = reinterpret_cast<uint8_t*>(g_scratch[3]);
            memset(g_scratch[4], 0, 256);
            auto* out_4 = reinterpret_cast<uint64_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<uint8_t*>(g_scratch[5]);
            memset(g_scratch[6], 0, 256);
            auto* out_6 = reinterpret_cast<uint8_t*>(g_scratch[6]);
            decode_nsm_code_auth_key_perm_update_req(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5, out_6);
            break;
        }
        case 15: {  // decode_nsm_code_auth_key_perm_update_resp
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
            decode_nsm_code_auth_key_perm_update_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 16: {  // decode_nsm_query_firmware_security_version_number_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_firmware_security_version_number_req*>(g_scratch[0]);
            decode_nsm_query_firmware_security_version_number_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 17: {  // decode_nsm_query_firmware_security_version_number_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_firmware_security_version_number_resp*>(g_scratch[2]);
            decode_nsm_query_firmware_security_version_number_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 18: {  // decode_nsm_firmware_update_sec_ver_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_firmware_update_min_sec_ver_req*>(g_scratch[0]);
            decode_nsm_firmware_update_sec_ver_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 19: {  // decode_nsm_firmware_update_sec_ver_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_firmware_update_min_sec_ver_resp*>(g_scratch[2]);
            decode_nsm_firmware_update_sec_ver_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 20: {  // decode_nsm_firmware_set_rot_property_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_firmware_set_rot_property_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 21: {  // decode_nsm_firmware_image_copy_control_query_progress_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            memset(g_scratch[2], 0, 256);
            auto* out_2 = reinterpret_cast<struct nsm_firmware_image_copy_control_query_progress_resp*>(g_scratch[2]);
            decode_nsm_firmware_image_copy_control_query_progress_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 22: {  // decode_nsm_firmware_image_copy_control_initiate_copy_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_firmware_image_copy_control_initiate_copy_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 23: {  // decode_nsm_dot_cak_install_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_dot_cak_install_req*>(g_scratch[0]);
            decode_nsm_dot_cak_install_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 24: {  // decode_nsm_dot_cak_install_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_dot_cak_install_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 25: {  // decode_nsm_dot_cak_bypass_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_nsm_dot_cak_bypass_req(msg, msg_buf.size());
            break;
        }
        case 26: {  // decode_nsm_dot_cak_bypass_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_dot_cak_bypass_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 27: {  // decode_nsm_dot_lock_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_dot_lock_req*>(g_scratch[0]);
            decode_nsm_dot_lock_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 28: {  // decode_nsm_dot_lock_resp
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
            decode_nsm_dot_lock_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 29: {  // decode_nsm_dot_unlock_challenge_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_dot_unlock_challenge_req*>(g_scratch[0]);
            decode_nsm_dot_unlock_challenge_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 30: {  // decode_nsm_dot_unlock_challenge_resp
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
            decode_nsm_dot_unlock_challenge_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 31: {  // decode_nsm_dot_unlock_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_dot_unlock_req*>(g_scratch[0]);
            decode_nsm_dot_unlock_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 32: {  // decode_nsm_dot_unlock_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_dot_unlock_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 33: {  // decode_nsm_dot_get_info_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_nsm_dot_get_info_req(msg, msg_buf.size());
            break;
        }
        case 34: {  // decode_nsm_dot_get_info_resp
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
            auto* out_4 = reinterpret_cast<uint8_t*>(g_scratch[4]);
            memset(g_scratch[5], 0, 256);
            auto* out_5 = reinterpret_cast<uint8_t*>(g_scratch[5]);
            decode_nsm_dot_get_info_resp(msg, msg_buf.size(), out_0, out_1, out_2, out_3, out_4, out_5);
            break;
        }
        case 35: {  // decode_nsm_dot_get_status_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            decode_nsm_dot_get_status_req(msg, msg_buf.size());
            break;
        }
        case 36: {  // decode_nsm_dot_get_status_resp
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
            decode_nsm_dot_get_status_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 37: {  // decode_nsm_dot_cak_rotate_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_dot_cak_rotate_req*>(g_scratch[0]);
            decode_nsm_dot_cak_rotate_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 38: {  // decode_nsm_dot_cak_rotate_resp
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
            decode_nsm_dot_cak_rotate_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 39: {  // decode_nsm_dot_override_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_dot_override_req*>(g_scratch[0]);
            decode_nsm_dot_override_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 40: {  // decode_nsm_dot_override_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_dot_override_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
        case 41: {  // decode_nsm_dot_disable_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_dot_disable_req*>(g_scratch[0]);
            decode_nsm_dot_disable_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 42: {  // decode_nsm_dot_disable_resp
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
            decode_nsm_dot_disable_resp(msg, msg_buf.size(), out_0, out_1, out_2);
            break;
        }
        case 43: {  // decode_nsm_dot_recovery_req
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<struct nsm_dot_recovery_req*>(g_scratch[0]);
            decode_nsm_dot_recovery_req(msg, msg_buf.size(), out_0);
            break;
        }
        case 44: {  // decode_nsm_dot_recovery_resp
            if (size < 1 + sizeof(struct nsm_msg_hdr)) return 0;
            std::vector<uint8_t> msg_buf(data + 1, data + size);
            if (!validate_nsm_msg_length(msg_buf.data(), msg_buf.size())) return 0;
            const auto* msg = reinterpret_cast<const struct nsm_msg*>(msg_buf.data());
            memset(g_scratch[0], 0, 256);
            auto* out_0 = reinterpret_cast<uint8_t*>(g_scratch[0]);
            memset(g_scratch[1], 0, 256);
            auto* out_1 = reinterpret_cast<uint16_t*>(g_scratch[1]);
            decode_nsm_dot_recovery_resp(msg, msg_buf.size(), out_0, out_1);
            break;
        }
    }

    return 0;
}
