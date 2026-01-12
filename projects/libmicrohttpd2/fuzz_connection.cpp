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
#include <stdlib.h>
#include <string.h>

#include "fuzzer/FuzzedDataProvider.h"
#include "connection_helper.h"
#include "conn_timeout.h"

#include "daemon_funcs.h"
#include "mempool_funcs.h"
#include "post_parser_funcs.h"
#include "stream_funcs.h"
#include "stream_process_request.h"


// Helper to fuzz mhd_stream_process_post_finish
static void fuzz_mhd_stream_process_post_finish(MHD_Connection& connection, MHD_Daemon& daemon, const std::string& body) {
  struct mhd_PostParserData *p = &connection.rq.u_proc.post;
  size_t pos  = p->next_parse_pos;
  size_t need = ((p->lbuf_used > pos) ? p->lbuf_used : pos) + 1; // +1 for NUL
  if (connection.rq.cntn.lbuf.size < need) {
    size_t delta = need - connection.rq.cntn.lbuf.size;
    if (delta != 0)
      mhd_daemon_extend_lbuf_up_to(&daemon, delta, &connection.rq.cntn.lbuf);
  }

  if (connection.rq.cntn.lbuf.data == nullptr && !body.empty()) {
    size_t to_copy = (body.size() < (size_t)p->lbuf_limit) ? body.size() : (size_t)p->lbuf_limit;
    size_t min_needed = to_copy + 1; // 1 byte for \0 terminator
    if (connection.rq.cntn.lbuf.size < min_needed) {
      size_t delta = min_needed - connection.rq.cntn.lbuf.size;
      if (delta != 0)
        mhd_daemon_extend_lbuf_up_to(&daemon, delta, &connection.rq.cntn.lbuf);
    }
    if (connection.rq.cntn.lbuf.data != nullptr) {
      memcpy(connection.rq.cntn.lbuf.data, body.data(), to_copy);
      p->lbuf_used = to_copy;
    }
  }

  // Fail back to Text encoding
  if (p->enc == MHD_HTTP_POST_ENCODING_OTHER) {
    p->enc = MHD_HTTP_POST_ENCODING_TEXT_PLAIN;
  }
  mhd_stream_prepare_for_post_parse(&connection);
  mhd_stream_process_post_finish(&connection);

  bool can_finish = (connection.rq.cntn.lbuf.data != nullptr);
  if (can_finish && connection.rq.u_proc.post.enc == MHD_HTTP_POST_ENCODING_FORM_URLENCODED) {
    size_t pos = connection.rq.u_proc.post.next_parse_pos;
    if (pos >= connection.rq.cntn.lbuf.size) {
      mhd_daemon_extend_lbuf_up_to(&daemon, 1, &connection.rq.cntn.lbuf);
      if (pos >= connection.rq.cntn.lbuf.size)
        can_finish = false;
    }
  }

  if (can_finish) {
    if (connection.rq.u_proc.post.enc == MHD_HTTP_POST_ENCODING_OTHER) {
      if (connection.rq.app_act.head_act.data.post_parse.enc == MHD_HTTP_POST_ENCODING_OTHER)
        connection.rq.app_act.head_act.data.post_parse.enc = MHD_HTTP_POST_ENCODING_TEXT_PLAIN;
      mhd_stream_prepare_for_post_parse(&connection);
    }
    mhd_stream_process_post_finish(&connection);
  }
}


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
    selectors.push_back(fdp.ConsumeIntegralInRange<int>(0, 9));
  }

  // Generate random body and stream it in the connection
  bool use_stream_body = fdp.ConsumeBool();

  // Use remaining bytes to generate random body for fuzzing
  std::string body = fdp.ConsumeRemainingBytesAsString();
  size_t body_size = body.size();
  if (body_size == 0) {
    return 0;
  }
  prepare_body_and_process(connection, body, body_size, use_stream_body);

  // Fuzz random round of target functions
  for (int selector : selectors) {
    switch (selector) {
      case 0: {
        mhd_stream_is_timeout_expired(&connection);
        break;
      }
      case 1: {
        mhd_stream_switch_to_rq_headers_proc(&connection);
        break;
      }
      case 2: {
        const struct MHD_UploadAction* act = &kContinueAction;
        mhd_stream_process_upload_action(&connection, &kContinueAction, false);
        mhd_stream_process_upload_action(&connection, &kSuspend, false);
        mhd_stream_process_upload_action(&connection, &kAbort, true);
        break;
      }
      case 3: {
        connection.stage = mhd_HTTP_STAGE_REQ_RECV_FINISHED;
        mhd_stream_process_req_recv_finished(&connection);
        break;
      }
      case 4: {
        mhd_stream_reset_rq_hdr_proc_state(&connection);
        break;
      }
      case 5: {
        mhd_stream_alloc_memory(&connection, 1024);
        break;
      }
      case 6: {
        // Safe guard for out of buffer space
        if (connection.write_buffer_send_offset > connection.write_buffer_append_offset) {
          connection.write_buffer_send_offset = connection.write_buffer_append_offset;
        }
        mhd_stream_maximize_write_buffer(&connection);
        break;
      }
      case 7: {
        // Safe guard for out of buffer space
        connection.write_buffer_send_offset = connection.write_buffer_append_offset;
        mhd_stream_release_write_buffer(&connection);
        break;
      }
      case 8: {
        // Safe guard for out of buffer read
        if (connection.read_buffer_offset > connection.read_buffer_size) {
          connection.read_buffer_offset = connection.read_buffer_size;
        }
        mhd_stream_shrink_read_buffer(&connection);
        break;
      }
      case 9: {
        mhd_stream_switch_from_recv_to_send(&connection);
        break;
      }
    }
  }

  // Fuzz mhd_stream_process_post_finish
  fuzz_mhd_stream_process_post_finish(connection, daemon, body);

  // Final cleanup to avoid memory leak
  final_cleanup(connection, daemon);

  return 0;
}
