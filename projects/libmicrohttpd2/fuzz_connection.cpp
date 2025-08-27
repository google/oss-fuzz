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

extern "C" {
  #include "mhd_connection.h"
  #include "mhd_action.h"
  #include "mhd_post_parser.h"
  #include "http_post_enc.h"
  #include "mempool_funcs.h"
  #include "mhd_daemon.h"
  #include "daemon_funcs.h"
  #include "microhttpd2.h"
  #include "post_parser_funcs.h"
  #include "stream_process_request.h"
  #include "stream_funcs.h"
}

// MHD memory pool
static struct mhd_MemoryPool *g_pool = nullptr;
static const size_t g_pool_size = 14 * 1024;

// Helper to clear memory pool
static void destroy_global_pool() {
  if (g_pool) { mhd_pool_destroy(g_pool); g_pool = nullptr; }
}

// Initialising the memory pool
extern "C" int LLVMFuzzerInitialize() {
  g_pool = mhd_pool_create(g_pool_size, MHD_MEMPOOL_ZEROING_ON_RESET);
  atexit(destroy_global_pool);
  return 0;
}

// Dummy upload actions
static const struct MHD_UploadAction kContinueAction = {
  mhd_UPLOAD_ACTION_CONTINUE, { nullptr }
};
static const struct MHD_UploadAction kSuspend = {
  mhd_UPLOAD_ACTION_SUSPEND, { nullptr }
};
static const struct MHD_UploadAction kAbort = {
  mhd_UPLOAD_ACTION_ABORT, { nullptr }
};

// Dummy reader function
static const struct MHD_UploadAction *
dummy_reader(struct MHD_Request*, void*, const struct MHD_String*,
             const struct MHD_StringNullable*, const struct MHD_StringNullable*,
             const struct MHD_StringNullable*, size_t, const void*,
             uint_fast64_t, enum MHD_Bool) {
  return &kContinueAction;
}

// Dummy connection request ending function
static const struct MHD_UploadAction *
dummy_done(struct MHD_Request*, void*, enum MHD_PostParseResult) {
  return &kContinueAction;
}

static void init_daemon_connection(FuzzedDataProvider& fdp,
                                   MHD_Daemon& d, MHD_Connection& c) {
  // Basic initialisation
  d = {};
  c = {};
  c.daemon = &d;
  c.pool = g_pool;

  // Configure daemon memory pool
  d.conns.cfg.mem_pool_size = g_pool_size;
  d.conns.cfg.mem_pool_zeroing = MHD_MEMPOOL_ZEROING_ON_RESET;

  // Confiugre daemon request
  d.req_cfg.large_buf.space_left = fdp.ConsumeIntegralInRange<size_t>(256, 65536);
  d.req_cfg.strictness = static_cast<enum MHD_ProtocolStrictLevel>(
      fdp.ConsumeIntegralInRange<int>(-1, 2));

  // Configure connection request and general settings
  c.rq.http_ver  = MHD_HTTP_VERSION_1_1;
  c.rq.http_mthd = static_cast<enum mhd_HTTP_Method>(
      fdp.ConsumeIntegralInRange<int>(0, 7));
  c.discard_request = false;
  c.suspended = false;
  c.connection_timeout_ms = fdp.ConsumeIntegralInRange<uint32_t>(0, 4096);
  c.last_activity = 0;
}

static void init_connection_buffer(FuzzedDataProvider& fdp, MHD_Connection& c) {
  // Prepare connection buffer in memory pool
  size_t required = 0;
  const size_t capacity = fdp.ConsumeIntegralInRange<size_t>(256, 8192);
  char* buf = static_cast<char*>(mhd_pool_try_alloc(c.pool, capacity, &required));
  if (!buf) {
    c.read_buffer = nullptr;
    c.read_buffer_size = 0;
    c.read_buffer_offset = 0;
    return;
  }

  // Inject random data to the connection buffer fpor fuzzing
  std::vector<char> data = fdp.ConsumeBytesWithTerminator<char>(capacity - 1, '\0');
  memcpy(buf, data.data(), data.size());

  c.read_buffer = buf;
  c.read_buffer_size = capacity;
  c.read_buffer_offset = data.size();

  // Configure post parsing state of the connection object
  c.rq.u_proc.post.parse_result   = MHD_POST_PARSE_RES_OK;
  c.rq.u_proc.post.next_parse_pos = 0;
}

static void init_parsing_configuration(FuzzedDataProvider& fdp, MHD_Connection& c, bool reset) {
  MHD_HTTP_PostEncoding enc = MHD_HTTP_POST_ENCODING_TEXT_PLAIN;

  if (!reset) {
    // Configure connection encoding abd methods
    c.rq.app_act.head_act.act = mhd_ACTION_POST_PARSE;
    if (fdp.ConsumeBool()) {
      enc = MHD_HTTP_POST_ENCODING_FORM_URLENCODED;
    } else if (fdp.ConsumeBool()) {
      enc = MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA;
    }

    c.rq.app_act.head_act.data.post_parse.buffer_size =
      fdp.ConsumeIntegralInRange<size_t>(1, 4096);
    c.rq.app_act.head_act.data.post_parse.max_nonstream_size =
      fdp.ConsumeIntegralInRange<size_t>(1, 4096);
  }

  // Confiugre head action for connection post parsing process
  c.rq.app_act.head_act.data.post_parse.enc = enc;
  c.rq.app_act.head_act.data.post_parse.stream_reader = dummy_reader;
  c.rq.app_act.head_act.data.post_parse.reader_cls = nullptr;
  c.rq.app_act.head_act.data.post_parse.done_cb = dummy_done;
  c.rq.app_act.head_act.data.post_parse.done_cb_cls = nullptr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || g_pool == nullptr) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Reseting the memory pool for each iteartion
  mhd_pool_reset(g_pool, nullptr, 0, g_pool_size);

  // Initialising the daemon, connection and other MHD components
  MHD_Daemon daemon;
  MHD_Connection connection;
  init_daemon_connection(fdp, daemon, connection);
  init_connection_buffer(fdp, connection);
  init_parsing_configuration(fdp, connection, false);

  // Randomly choose how many targets to fuzz
  std::vector<int> selectors;
  for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(1, 8); i++) {
    selectors.push_back(fdp.ConsumeIntegralInRange<int>(0, 11));
  }

  // Use remaining bytes to generate random body for fuzzing
  std::string body = fdp.ConsumeRemainingBytesAsString();
  size_t body_size = body.size();
  if (body_size == 0) {
    return 0;
  }

  // Fuzz mhd_stream_prepare_for_post_parse once
  mhd_stream_prepare_for_post_parse(&connection);

  // Fuzz mhd_stream_post_parse
  mhd_stream_post_parse(&connection, &body_size, body.data());

  // Fuzz random round of target functions
  for (int selector : selectors) {
    switch (selector) {
      case 0: {
        mhd_stream_is_timeout_expired(&connection);
        break;
      }
      case 1: {
        connection.stage = mhd_HTTP_STAGE_REQ_LINE_RECEIVING;
        mhd_stream_get_request_line(&connection);
        break;
      }
      case 2: {
        mhd_stream_switch_to_rq_headers_proc(&connection);
        break;
      }
      case 3: {
        // Ensure reparisng of the body
        init_parsing_configuration(fdp, connection, true);
        mhd_stream_prepare_for_post_parse(&connection);
        mhd_stream_post_parse(&connection, &body_size, body.data());
        connection.stage = mhd_HTTP_STAGE_BODY_RECEIVING;
        connection.rq.have_chunked_upload = ((reinterpret_cast<uintptr_t>(&connection) & 1) != 0);
        connection.rq.cntn.cntn_size = connection.rq.have_chunked_upload ? 0 : connection.read_buffer_offset;
        mhd_stream_process_request_body(&connection);
        break;
      }
      case 4: {
        const struct MHD_UploadAction* act = &kContinueAction;
        mhd_stream_process_upload_action(&connection, &kContinueAction, false);
        mhd_stream_process_upload_action(&connection, &kSuspend, false);
        mhd_stream_process_upload_action(&connection, &kAbort, true);
        break;
      }
      case 5: {
        connection.stage = mhd_HTTP_STAGE_REQ_RECV_FINISHED;
        mhd_stream_process_req_recv_finished(&connection);
        break;
      }
      case 6: {
        mhd_stream_reset_rq_hdr_proc_state(&connection);
        break;
      }
      case 7: {
        mhd_stream_alloc_memory(&connection, 1024);
        break;
      }
      case 8: {
        // Safe guard for out of buffer space
        if (connection.write_buffer_send_offset > connection.write_buffer_append_offset) {
          connection.write_buffer_send_offset = connection.write_buffer_append_offset;
        }
        mhd_stream_maximize_write_buffer(&connection);
        break;
      }
      case 9: {
        // Safe guard for out of buffer space
        connection.write_buffer_send_offset = connection.write_buffer_append_offset;
        mhd_stream_release_write_buffer(&connection);
        break;
      }
      case 10: {
        // Safe guard for out of buffer read
        if (connection.read_buffer_offset > connection.read_buffer_size) {
          connection.read_buffer_offset = connection.read_buffer_size;
        }
        mhd_stream_shrink_read_buffer(&connection);
        break;
      }
      default: case 11: {
        mhd_stream_switch_from_recv_to_send(&connection);
        break;
      }
    }
  }

  // Release buffers in daemon to avoid memory leakage
  if (connection.rq.cntn.lbuf.data != nullptr || connection.rq.cntn.lbuf.size != 0) {
    mhd_daemon_free_lbuf(&daemon, &connection.rq.cntn.lbuf);
  }

  return 0;
}
