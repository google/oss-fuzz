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
#include <vector>

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
  #include "response_funcs.h"
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

  if (c.rq.app_act.head_act.data.post_parse.enc == MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) {
    // Prepare buffer and header for multipart form encoding
    std::string boundary = "fuzz" + std::to_string(fdp.ConsumeIntegral<uint32_t>());
    std::string req = "POST /upload HTTP/1.1\r\nHost: fuzz\r\nContent-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n";
    const size_t n = (req.size() <= capacity) ? req.size() : capacity;
    memcpy(buf, req.data(), n);

    c.read_buffer = buf;
    c.read_buffer_size = capacity;
    c.read_buffer_offset = n;

    std::string marker = "--" + boundary + "--\r\n";
    size_t mlen = marker.size();
    if (c.read_buffer_offset + mlen < c.read_buffer_size) {
      memcpy(c.read_buffer + c.read_buffer_offset, marker.data(), mlen);
      c.read_buffer_offset += mlen;
    }
  } else {
    // Preprae buffer and header for other encoding
    const MHD_HTTP_PostEncoding enc = c.rq.app_act.head_act.data.post_parse.enc;
    const char* ct = "application/x-www-form-urlencoded";
    if (enc == MHD_HTTP_POST_ENCODING_FORM_URLENCODED) {
      ct = "application/x-www-form-urlencoded";
    } else if (enc == MHD_HTTP_POST_ENCODING_TEXT_PLAIN) {
      ct = "text/plain";
    } else if (enc == MHD_HTTP_POST_ENCODING_OTHER) {
      ct = fdp.ConsumeBool() ? "application/x-www-form-urlencoded" : "text/plain";
    }
    const std::string req = std::string("POST / HTTP/1.1\r\nHost: fuzz\r\nContent-Type: ") + ct + "\r\n\r\n";
    const size_t n = (req.size() <= capacity) ? req.size() : capacity;
    memcpy(buf, req.data(), n);

    size_t tail_cap = (capacity > n) ? (capacity - n) : 0;
    std::vector<char> data = fdp.ConsumeBytesWithTerminator<char>(
        tail_cap > 0 ? (tail_cap - (tail_cap > 0)) : 0, '\0');
    if (!data.empty())
      memcpy(buf + n, data.data(), data.size());

    c.read_buffer = buf;
    c.read_buffer_size = capacity;
    c.read_buffer_offset = n + data.size();

  }

  // Configure post parsing state of the connection object
  c.rq.u_proc.post.parse_result = MHD_POST_PARSE_RES_OK;
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
    } else {
      enc = MHD_HTTP_POST_ENCODING_OTHER;
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
  mhd_pool_destroy(g_pool);
  g_pool = mhd_pool_create(g_pool_size, MHD_MEMPOOL_ZEROING_ON_RESET);

  // Initialising the daemon, connection and other MHD components
  MHD_Daemon daemon;
  MHD_Connection connection;
  init_daemon_connection(fdp, daemon, connection);
  init_parsing_configuration(fdp, connection, false);
  init_connection_buffer(fdp, connection);

  // If we wrote a real HTTP header for multipart, parse it so Content-Type is visible
  connection.stage = mhd_HTTP_STAGE_REQ_LINE_RECEIVING;
  mhd_stream_get_request_line(&connection);
  mhd_stream_switch_to_rq_headers_proc(&connection);

  // Randomly choose how many targets to fuzz
  std::vector<int> selectors;
  for (int i = 0; i < fdp.ConsumeIntegralInRange<int>(1, 8); i++) {
    selectors.push_back(fdp.ConsumeIntegralInRange<int>(0, 9));
  }

  // Randomly choose data preparation approach
  bool use_stream_body = fdp.ConsumeBool();

  // Use remaining bytes to generate random body for fuzzing
  std::string body = fdp.ConsumeRemainingBytesAsString();
  size_t body_size = body.size();
  if (body_size == 0) {
    return 0;
  }

  // If multipart was selected, wrap the payload into a minimal valid multipart body using the boundary marker we stored.
  if (connection.rq.app_act.head_act.data.post_parse.enc == MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA) {
    // Recover boundary from the tail marker we appended in init_connection_buffer: look for "\r\n--<b>--\r\n"
    std::string b;
    if (connection.read_buffer && connection.read_buffer_offset > 10) {
      const char* start = static_cast<const char*>(memchr(connection.read_buffer, '-', connection.read_buffer_offset));
      if (start) {
        const char* end = static_cast<const char*>(memmem(start, connection.read_buffer + connection.read_buffer_offset - start, "--\r\n", 4));
        if (end && end > start) {
          b.assign(start + 2, end - (start + 2));
        }
      }
    }
    if (!b.empty()) {
      std::string wrapped;
      wrapped.reserve(body.size() + b.size() * 2 + 64);
      wrapped += "--"; wrapped += b; wrapped += "\r\n";
      wrapped += "Content-Disposition: form-data; name=\"x\"\r\n\r\n";
      wrapped += body; wrapped += "\r\n";
      wrapped += "--"; wrapped += b; wrapped += "--\r\n";
      body.swap(wrapped);
      body_size = body.size();
    }
  }

  if (!use_stream_body) {
    // Fuzz mhd_stream_prepare_for_post_parse once and mhd_stream_post_parse
    mhd_stream_prepare_for_post_parse(&connection);
    mhd_stream_post_parse(&connection, &body_size, &body[0]);
  } else {
    // Try prepare the body by streaming connection buffer
    bool staged = false;
    if (connection.read_buffer && connection.read_buffer_size >= body_size) {
      memcpy(connection.read_buffer, body.data(), body_size);
      connection.read_buffer_offset = body_size;
      staged = true;
    } else {
      size_t need = 0;
      char *nb = (char*) mhd_pool_try_alloc(connection.pool, body_size, &need);
      if (nb) {
        memcpy(nb, body.data(), body_size);
        connection.read_buffer = nb;
        connection.read_buffer_size = body_size;
        connection.read_buffer_offset = body_size;
        staged = true;
      }
    }

    if (staged) {
      // Use stream body approach if success
      connection.stage = mhd_HTTP_STAGE_BODY_RECEIVING;
      connection.rq.have_chunked_upload = false;
      connection.rq.cntn.cntn_size = (uint64_t) body_size;
      mhd_stream_prepare_for_post_parse(&connection);
      mhd_stream_process_request_body(&connection);
    } else {
      // Use post prase approach if stream body failed
      mhd_stream_prepare_for_post_parse(&connection);
      mhd_stream_post_parse(&connection, &body_size, &body[0]);
    }
  }

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
  if (connection.rq.cntn.lbuf.data) {
    // Check if mhd_stream_process_post_finish can be called
    bool can_finish = true;
    if (connection.rq.u_proc.post.enc == MHD_HTTP_POST_ENCODING_FORM_URLENCODED) {
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

  // Release buffers in daemon to avoid memory leakage
  if (connection.rq.cntn.lbuf.data != nullptr || connection.rq.cntn.lbuf.size != 0) {
    mhd_daemon_free_lbuf(&daemon, &connection.rq.cntn.lbuf);
  }

  return 0;
}
