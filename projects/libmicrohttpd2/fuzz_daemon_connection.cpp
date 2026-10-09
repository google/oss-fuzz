// Copyright 2025 Google LLC
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
#include <string>
#include <vector>
#include <cstring>

#include "fuzzer/FuzzedDataProvider.h"
#include "connection_helper.h"

#include "conn_tls_check.h"
#include "mempool_funcs.h"
#include "mhd_send.h"
#include "stream_process_request.h"
#include "stream_process_states.h"


// Initialising the memory pool
extern "C" int LLVMFuzzerInitialize() {
  g_pool = mhd_pool_create(g_pool_size, MHD_MEMPOOL_ZEROING_ON_RESET);
  atexit(destroy_global_pool);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || g_pool == nullptr) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Reseting the memory pool for each iteartion
  mhd_pool_destroy(g_pool);
  g_pool = mhd_pool_create(g_pool_size, MHD_MEMPOOL_ZEROING_ON_RESET);

  // Initialising the daemon, connection and other MHD components
  MHD_Daemon daemon;
  MHD_Connection connection;
  init_daemon_connection(fdp, daemon, connection);
  init_parsing_configuration(fdp, connection);
  init_connection_buffer(fdp, connection);
  prepare_headers_and_parse(connection, size);

  // Randomly choose how many targets to fuzz
  std::vector<int> selectors;
  for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(1, 8); i++) {
    selectors.push_back(fdp.ConsumeIntegralInRange<int>(0, 5));
  }

  // Generate random flags
  bool use_stream_body = fdp.ConsumeBool();
  bool is_nodelay = fdp.ConsumeBool();
  bool is_cork = fdp.ConsumeBool();

  // Use remaining bytes to generate random body for fuzzing
  std::string body = fdp.ConsumeRemainingBytesAsString();
  size_t body_size = body.size();
  if (body_size == 0) {
    return 0;
  }
  prepare_body_and_process(connection, body, body_size, use_stream_body);

  for (int selector : selectors) {
    switch (selector) {
      case 0: {
        mhd_conn_event_loop_state_update(&connection);
        break;
      }
      case 1: {
        if (connection.rq.app_act.head_act.act == mhd_ACTION_NO_ACTION &&
            connection.daemon && connection.daemon->req_cfg.cb) {
          mhd_stream_call_app_request_cb(&connection);
        }
        break;
      }
      case 2: {
        if (connection.rq.app_act.head_act.act == mhd_ACTION_POST_PARSE &&
            connection.rq.app_act.head_act.data.post_parse.done_cb != nullptr &&
            is_post_parse_ready(connection)) {
          mhd_stream_process_req_recv_finished(&connection);
        }
        break;
      }
      default: case 3: {
        mhd_conn_tls_check(&connection);
        break;
      }
    }
  }

  final_cleanup(connection, daemon);
  return 0;
}
