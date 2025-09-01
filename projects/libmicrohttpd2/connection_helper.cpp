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
#include "connection_helper.h"
#include <cstring>

extern "C" {
  #include "mhd_action.h"
  #include "http_post_enc.h"
  #include "mempool_funcs.h"
  #include "daemon_funcs.h"
  #include "post_parser_funcs.h"
  #include "response_funcs.h"
  #include "stream_process_request.h"
  #include "stream_funcs.h"
}

// MHD memory pool
struct mhd_MemoryPool *g_pool = nullptr;
const size_t g_pool_size = 14 * 1024;
std::string g_mpart_boundary;

// Helper to clear memory pool
void destroy_global_pool() {
  if (g_pool) { mhd_pool_destroy(g_pool); g_pool = nullptr; }
}

// Dummy upload actions
const struct MHD_UploadAction kContinueAction = {
  mhd_UPLOAD_ACTION_CONTINUE, { nullptr }
};
const struct MHD_UploadAction kSuspend = {
  mhd_UPLOAD_ACTION_SUSPEND, { nullptr }
};
const struct MHD_UploadAction kAbort = {
  mhd_UPLOAD_ACTION_ABORT, { nullptr }
};

// Dummy reader function
const struct MHD_UploadAction *
dummy_reader(struct MHD_Request*, void*, const struct MHD_String*,
             const struct MHD_StringNullable*, const struct MHD_StringNullable*,
             const struct MHD_StringNullable*, size_t, const void*,
             uint_fast64_t, enum MHD_Bool) {
  return &kContinueAction;
}

// Dummy connection request ending function
const struct MHD_UploadAction *
dummy_done(struct MHD_Request*, void*, enum MHD_PostParseResult) {
  return &kContinueAction;
}

void init_daemon_connection(FuzzedDataProvider& fdp,
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
      fdp.ConsumeIntegralInRange<int>(0, 2));

  // Configure connection request and general settings
  c.discard_request = false;
  c.suspended = false;
  c.connection_timeout_ms = fdp.ConsumeIntegralInRange<uint32_t>(0, 4096);
  c.last_activity = 0;
}

void init_connection_buffer(FuzzedDataProvider& fdp, MHD_Connection& c) {
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

  // Always craft a full request line with headers
  const MHD_HTTP_PostEncoding enc = c.rq.app_act.head_act.data.post_parse.enc;
  std::string req;
  req.reserve(256);
  req += "POST /upload HTTP/1.1\r\nHost: fuzz\r\nContent-Type: ";
  bool detect_mpart = false;
  switch (enc) {
    case MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA:
      g_mpart_boundary = "fuzz" + std::to_string(fdp.ConsumeIntegral<uint32_t>());
      req += "multipart/form-data; boundary=" + g_mpart_boundary;
      break;
    case MHD_HTTP_POST_ENCODING_FORM_URLENCODED:
      req += "application/x-www-form-urlencoded";
      break;
    case MHD_HTTP_POST_ENCODING_TEXT_PLAIN:
      req += "text/plain";
      break;
    case MHD_HTTP_POST_ENCODING_OTHER:
    default:
      // low-probability detection lane to trigger detect_* from headers
      detect_mpart = fdp.ConsumeBool();
      if (detect_mpart) {
        g_mpart_boundary = "fuzz" + std::to_string(fdp.ConsumeIntegral<uint32_t>());
        req += "multipart/form-data; boundary=" + g_mpart_boundary;
      } else {
        req += (fdp.ConsumeBool() ? "application/x-www-form-urlencoded" : "text/plain");
      }
      break;
  }
  req += "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  const size_t n = (req.size() <= capacity) ? req.size() : capacity;
  memcpy(buf, req.data(), n);
  c.read_buffer = buf;
  c.read_buffer_size = capacity;
  c.read_buffer_offset = n;
}

void init_parsing_configuration(FuzzedDataProvider& fdp, MHD_Connection& c) {
  MHD_HTTP_PostEncoding enc;

  // Configure connection encoding abd methods
  c.rq.app_act.head_act.act = mhd_ACTION_POST_PARSE;
  if (fdp.ConsumeBool()) {
    enc = MHD_HTTP_POST_ENCODING_TEXT_PLAIN;
  } else if (fdp.ConsumeBool()) {
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

  // Confiugre head action for connection post parsing process
  c.rq.app_act.head_act.data.post_parse.enc = enc;
  c.rq.app_act.head_act.data.post_parse.stream_reader = dummy_reader;
  c.rq.app_act.head_act.data.post_parse.reader_cls = nullptr;
  c.rq.app_act.head_act.data.post_parse.done_cb = dummy_done;
  c.rq.app_act.head_act.data.post_parse.done_cb_cls = nullptr;
}

void prepare_headers_and_parse(MHD_Connection& connection, size_t size) {
  // Manually add a parameter for parsing
  auto add_hdr = [&](const char* name_c, const std::string& val_s) {
    const size_t nlen = strlen(name_c);
    const size_t vlen = val_s.size();
    char* nbuf = static_cast<char*>(mhd_stream_alloc_memory(&connection, nlen + 1));
    char* vbuf = static_cast<char*>(mhd_stream_alloc_memory(&connection, vlen + 1));
    if (!nbuf || !vbuf) {
      return;
    }
    memcpy(nbuf, name_c, nlen); nbuf[nlen] = '\0';
    memcpy(vbuf, val_s.data(), vlen); vbuf[vlen] = '\0';
    struct MHD_String name;
    name.len  = nlen;
    name.cstr = nbuf;
    struct MHD_String value;
    value.len  = vlen;
    value.cstr = vbuf;
    mhd_stream_add_field(&connection, MHD_VK_HEADER, &name, &value);
  };
  add_hdr("Host", "fuzz");

  bool force_mpart = (connection.rq.app_act.head_act.data.post_parse.enc
                        == MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA);
  if (!force_mpart) {
    force_mpart = ((size & 0x3Fu) == 0u);
  }
  if (force_mpart) {
    if (g_mpart_boundary.empty()) {
      g_mpart_boundary = "fuzz" + std::to_string(size ^ 0x9e3779b97f4a7c15ULL);
    }
    std::string ct = "multipart/form-data; boundary=" + g_mpart_boundary;
    add_hdr("Content-Type", ct);
  }

  // If we wrote a real HTTP header for multipart, parse it so Content-Type is visible
  connection.stage = mhd_HTTP_STAGE_INIT;
  bool got_line = mhd_stream_get_request_line(&connection);
  if (got_line && connection.stage == mhd_HTTP_STAGE_REQ_LINE_RECEIVED) {
    mhd_stream_switch_to_rq_headers_proc(&connection);
  }
  mhd_stream_parse_request_headers(&connection);

  // Only proceed to post-parse if header parsing did not bail out
  bool headers_ok = (connection.stage != mhd_HTTP_STAGE_START_REPLY);
  if (!headers_ok && connection.rp.response) {
    MHD_response_destroy(connection.rp.response);
    connection.rp.response = nullptr;
  }
}

void prepare_body_and_process(MHD_Connection& connection, std::string& body, size_t body_size, bool use_stream_body) {
  // Use streaming if boundary is not empty
  if (!g_mpart_boundary.empty()) {
    std::string wrapped;
    wrapped.reserve(body.size() + g_mpart_boundary.size() * 2 + 128);
    wrapped += "\r\n--"; wrapped += g_mpart_boundary; wrapped += "\r\n";
    wrapped += "Content-Disposition: form-data; name=\"x\"; filename=\"f\"\r\n";
    wrapped += "Content-Type: application/octet-stream\r\n\r\n";
    wrapped += body; wrapped += "\r\n";
    wrapped += "--"; wrapped += g_mpart_boundary; wrapped += "--\r\n";
    body.swap(wrapped);
    body_size = body.size();
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
      connection.rq.have_chunked_upload = MHD_NO;
      connection.rq.cntn.cntn_size = (uint64_t) body_size;
      mhd_stream_prepare_for_post_parse(&connection);
      mhd_stream_process_request_body(&connection);
    } else {
      // Use post prase approach if stream body failed
      mhd_stream_prepare_for_post_parse(&connection);
      mhd_stream_post_parse(&connection, &body_size, &body[0]);
    }
  }
}

void final_cleanup(MHD_Connection& connection, MHD_Daemon& daemon) {
  // Post process response
  mhd_stream_switch_from_recv_to_send(&connection);
  mhd_stream_process_req_recv_finished(&connection);
  mhd_stream_release_write_buffer(&connection);

  // Release buffers in daemon to avoid memory leakage
  if (connection.rq.cntn.lbuf.data != nullptr || connection.rq.cntn.lbuf.size != 0) {
    mhd_daemon_free_lbuf(&daemon, &connection.rq.cntn.lbuf);
  }
}
