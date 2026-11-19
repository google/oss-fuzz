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
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "base.h"
#include "fpga-controller.h"
#include "fpga-maps.h"
#include "fpga-run.h"
#include "fpga-tables.h"
}

namespace {

template <typename T>
T consume_pod(const uint8_t*& ptr, size_t& rem) {
    T out{};
    size_t n = std::min(rem, sizeof(T));
    if (n > 0) {
        std::memcpy(&out, ptr, n);
        ptr += n;
        rem -= n;
    }
    return out;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) {
        return 0;
    }

    const uint8_t* ptr = data;
    size_t rem = size;
    uint8_t mode = consume_pod<uint8_t>(ptr, rem);
    const struct nsm_fpga_map* map = nsm_fpga_map_p0();

    switch (mode % 3) {
        case 0: {
            // Exercise 32-byte FPGA MMIO record decoders, classifiers & planners.
            if (rem < NSM_FPGA_RECORD_SIZE) {
                return 0;
            }
            std::vector<uint8_t> rec(ptr, ptr + NSM_FPGA_RECORD_SIZE);
            ptr += NSM_FPGA_RECORD_SIZE;
            rem -= NSM_FPGA_RECORD_SIZE;

            struct nsm_fpga_identity id = consume_pod<struct nsm_fpga_identity>(ptr, rem);
            uint8_t opcode = consume_pod<uint8_t>(ptr, rem);
            uint8_t station = consume_pod<uint8_t>(ptr, rem);
            uint8_t mask = consume_pod<uint8_t>(ptr, rem);
            uint32_t argument = consume_pod<uint32_t>(ptr, rem);
            uint64_t address = consume_pod<uint64_t>(ptr, rem);
            uint64_t epoch = consume_pod<uint64_t>(ptr, rem);

            (void)nsm_fpga_identity_valid(&id);
            (void)nsm_fpga_i2c_argument_valid(argument);
            (void)nsm_fpga_xfer_opcode_valid(opcode);

            struct nsm_fpga_control_completion ctrl_comp = {};
            if (nsm_fpga_decode_control_completion(rec.data(), &ctrl_comp) == 0) {
                (void)nsm_fpga_match_control(&ctrl_comp, &id, opcode, argument);
                (void)nsm_fpga_control_result_name(ctrl_comp.result);
            }

            struct nsm_fpga_word_completion word_comp = {};
            if (nsm_fpga_decode_word_completion(rec.data(), &word_comp) == 0) {
                (void)nsm_fpga_match_word(&word_comp, &id, opcode);
            }

            struct nsm_fpga_authority_status auth = {};
            if (nsm_fpga_decode_authority_status(rec.data(), &auth) == 0) {
                (void)nsm_fpga_session_classify(&auth);
                (void)nsm_fpga_authority_acquirable(&auth);
                (void)nsm_fpga_authority_recoverable(&auth);
                (void)nsm_fpga_authority_activatable(&auth);
                uint64_t out_epoch = 0;
                uint32_t out_gen = 0;
                (void)nsm_fpga_grant_from_authority(&auth, id.session, &out_epoch, &out_gen);
            }

            uint8_t result = 0;
            uint8_t fault_reason = 0;
            uint8_t data_byte = 0;
            uint32_t word_data = 0;
            bool nack = false;
            enum nsm_fpga_reply r1 =
                nsm_fpga_classify_control(rec.data(), &id, opcode, argument, &result);
            (void)nsm_fpga_reply_name(r1);
            (void)nsm_fpga_classify_authority(rec.data(), epoch, opcode, &result);
            (void)nsm_fpga_classify_word(rec.data(), &id, opcode, &word_data, &fault_reason);
            (void)nsm_fpga_classify_i2c_byte(rec.data(), &id, argument, &data_byte, &nack);
            (void)nsm_fpga_classify_i2c_xfer(
                rec.data(), &id, opcode, &word_data, &nack, &fault_reason);

            uint8_t enc_rec[NSM_FPGA_RECORD_SIZE] = {};
            (void)nsm_fpga_encode_control(&id, opcode, argument, enc_rec);
            (void)nsm_fpga_encode_word_compact(&id, station, opcode, mask, address, argument, enc_rec);
            (void)nsm_fpga_encode_byte_header(&id, station, argument, enc_rec);
            (void)nsm_fpga_encode_xfer_header(&id, station, opcode, argument, enc_rec);

            struct nsm_fpga_grant grant = {id.epoch, id.session, id.generation};
            struct nsm_fpga_step steps[NSM_FPGA_PLAN_MAX_STEPS] = {};
            (void)nsm_fpga_plan_control(&map->window, &grant, opcode, id.sequence, argument, steps);
            (void)nsm_fpga_plan_word_compact(
                &map->window, &grant, id.sequence, station, opcode, address, argument, steps);
            (void)nsm_fpga_plan_i2c_byte(&map->window, &grant, id.sequence, station, argument, steps);
            (void)nsm_fpga_plan_i2c_xfer(
                &map->window, &grant, id.sequence, station, opcode, argument, steps);
            (void)nsm_fpga_plan_authority(&map->window, opcode, epoch, steps);
            (void)nsm_fpga_plan_recover(&map->window, epoch, steps);
            (void)nsm_fpga_plan_status_read(&map->window, &steps[0]);
            break;
        }

        case 1: {
            // Exercise table/rule decoders, numeric/identity extraction & map lookups.
            uint8_t part_sel = consume_pod<uint8_t>(ptr, rem);
            uint8_t rule_sel = consume_pod<uint8_t>(ptr, rem);
            uint8_t station_sel = consume_pod<uint8_t>(ptr, rem);
            uint32_t word_val = consume_pod<uint32_t>(ptr, rem);

            size_t str_len = std::min<size_t>(rem / 3, 64);
            std::string query(reinterpret_cast<const char*>(ptr), str_len);
            ptr += str_len;
            rem -= str_len;

            (void)nsm_fpga_map_identity_by_platform(query.c_str());
            (void)nsm_fpga_station_by_selector(map, station_sel);
            (void)nsm_fpga_find_rule(map, query.c_str());
            (void)nsm_fpga_find_group(map, query.c_str());
            (void)nsm_fpga_sdm_word_legal(part_sel, rule_sel * 4ULL, word_val, station_sel);
            (void)nsm_fpga_word_legal(map, station_sel, part_sel, rule_sel * 4ULL, word_val, 0x0f);

            size_t half = rem / 2;
            std::vector<uint8_t> item_buf(ptr, ptr + half);
            std::vector<uint8_t> group_buf(ptr + half, ptr + rem);

            if (map->part_count > 0) {
                const struct nsm_fpga_part* part = map->parts[part_sel % map->part_count];
                if (part->rule_count > 0) {
                    const struct nsm_fpga_rule* rule = &part->rules[rule_sel % part->rule_count];
                    (void)nsm_fpga_rule_valid(map, rule);
                    uint32_t decoded_word = 0;
                    if (nsm_fpga_rule_word(
                            rule, item_buf.data(), item_buf.size(),
                            group_buf.data(), group_buf.size(), &decoded_word)) {
                        uint8_t st = 0, hl = 0;
                        (void)nsm_fpga_decode_state(rule, decoded_word, &st, &hl);
                    }
                    double num_val = 0.0;
                    (void)nsm_fpga_decode_numeric(
                        &rule->numeric, item_buf.data(), item_buf.size(),
                        group_buf.data(), group_buf.size(), &num_val);
                    (void)nsm_fpga_decode_element(
                        &rule->numeric, station_sel % 8, item_buf.data(), item_buf.size(),
                        group_buf.data(), group_buf.size(), &num_val);
                    size_t id_cnt = 0;
                    const struct nsm_fpga_identity_field* fields =
                        nsm_fpga_rule_identity(rule, &id_cnt);
                    for (size_t i = 0; i < id_cnt; ++i) {
                        char id_text[NSM_FPGA_IDENTITY_TEXT_MAX] = {};
                        (void)nsm_fpga_decode_identity(
                            &fields[i], item_buf.data(), item_buf.size(),
                            group_buf.data(), group_buf.size(), id_text, sizeof(id_text));
                    }
                    (void)nsm_fpga_compare_holds(
                        &rule->valid_if, item_buf.data(), item_buf.size(),
                        group_buf.data(), group_buf.size(), word_val);
                }
            }
            break;
        }

        case 2: {
            // Exercise stateful nsm_fpga_run row/control/status/recover state machine.
            uint8_t job_sel = consume_pod<uint8_t>(ptr, rem);
            uint8_t part_sel = consume_pod<uint8_t>(ptr, rem);
            uint8_t rule_sel = consume_pod<uint8_t>(ptr, rem);
            uint32_t arg = consume_pod<uint32_t>(ptr, rem);

            struct nsm_fpga_session session = {{1, 1, 1}, 0, 0};
            struct nsm_fpga_run_limits limits = {1, 4, 2};
            struct nsm_fpga_run run = {};
            nsm_fpga_run_init(&run, map, &session, &limits);
            nsm_fpga_run_begin_round(&run);
            nsm_fpga_run_begin_item(&run);

            switch (job_sel % 5) {
                case 0: {
                    if (map->part_count > 0) {
                        const struct nsm_fpga_part* part = map->parts[part_sel % map->part_count];
                        if (part->rule_count > 0) {
                            const struct nsm_fpga_rule* rule =
                                &part->rules[rule_sel % part->rule_count];
                            nsm_fpga_run_rows(&run, rule->commands, rule->command_count);
                        }
                    }
                    break;
                }
                case 1:
                    nsm_fpga_run_control(&run, NSM_FPGA_CTRL_ACQUIRE + (rule_sel % 3), arg);
                    break;
                case 2:
                    nsm_fpga_run_status(&run);
                    break;
                case 3:
                    nsm_fpga_run_recover(&run, 2 + (arg % 16));
                    break;
                case 4:
                    nsm_fpga_run_activate(&run, 1 + (arg % 16));
                    break;
            }

            for (int step_iter = 0; step_iter < 32; ++step_iter) {
                const struct nsm_fpga_step* step = nullptr;
                enum nsm_fpga_run_action action = nsm_fpga_run_next(&run, &step);
                if (action == NSM_FPGA_RUN_DONE || action == NSM_FPGA_RUN_FAILED) {
                    break;
                }
                if (action == NSM_FPGA_RUN_WAIT) {
                    continue;
                }
                if (action == NSM_FPGA_RUN_SEND && step != nullptr) {
                    uint8_t flags = consume_pod<uint8_t>(ptr, rem);
                    bool lost = (flags & 1) != 0;
                    bool no_session = (flags & 2) != 0;
                    if (step->kind == NSM_FPGA_STEP_WRITE) {
                        nsm_fpga_run_reply(&run, nullptr, lost, no_session);
                    } else {
                        if (rem < NSM_FPGA_RECORD_SIZE) {
                            nsm_fpga_run_abort(&run, "eof");
                            break;
                        }
                        std::vector<uint8_t> reply(ptr, ptr + NSM_FPGA_RECORD_SIZE);
                        ptr += NSM_FPGA_RECORD_SIZE;
                        rem -= NSM_FPGA_RECORD_SIZE;
                        nsm_fpga_run_reply(&run, reply.data(), lost, no_session);
                    }
                }
            }
            nsm_fpga_run_default_capture(&run);
            break;
        }
    }

    return 0;
}
