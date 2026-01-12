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
#include <unordered_set>

#include "mhd_action.h"
#include "http_post_enc.h"
#include "mempool_funcs.h"
#include "daemon_funcs.h"
#include "post_parser_funcs.h"
#include "response_funcs.h"
#include "stream_process_request.h"
#include "stream_funcs.h"


// MHD memory pool
struct mhd_MemoryPool *g_pool = nullptr;
const size_t g_pool_size = 14 * 1024;
std::string g_mpart_boundary;

// Body status
static std::unordered_set<const MHD_Connection*> g_post_parse_ready;

// Helper to clear memory pool
void destroy_global_pool() {
  if (g_pool) { mhd_pool_destroy(g_pool); g_pool = nullptr; }
}


// Helper to set body parsing ready
void mark_post_parse_ready(MHD_Connection& c) {
  g_post_parse_ready.insert(&c);
}

// Helper to check parse body status
bool is_post_parse_ready(const MHD_Connection& c) {
  return g_post_parse_ready.find(&c) != g_post_parse_ready.end();
}

// Helper to clear parse body status
void clear_post_parse_ready(const MHD_Connection& c) {
  g_post_parse_ready.erase(&c);
}

// Helper to destroy error response
static bool destroy_error_response(MHD_Connection c) {
  if (c.stage == mhd_HTTP_STAGE_START_REPLY) {
    MHD_response_destroy(c.rp.response);
    c.rp.response = nullptr;
    return true;
  }

  return false;
}

// Helper to randomly choose HTTP methods
static std::string pick_method(FuzzedDataProvider& fdp) {
  static const char* kMethods[] = {
    "GET","POST","PUT","HEAD","DELETE","CONNECT","OPTIONS","TRACE","*"
  };
  return std::string(fdp.PickValueInArray(kMethods));
}

// Helper to randomly choose http versions
static std::string pick_http_version(FuzzedDataProvider& fdp) {
  // Common + a chance to be malformed to trigger version errors.
  switch (fdp.ConsumeIntegralInRange<int>(0, 5)) {
    case 0: return "HTTP/1.1";
    case 1: return "HTTP/1.0";
    case 2: return "HTTP/2.0";
    case 3: return "HTTP/0.9";
    case 4: return "HTTX/1.1";
    default: {
      std::string s = "HTTP/";
      s.push_back(char('0' + fdp.ConsumeIntegralInRange<int>(0,9)));
      s.push_back('.');
      s.push_back(char('0' + fdp.ConsumeIntegralInRange<int>(0,9)));
      return s;
    }
  }
}

// Helper to check and expand buffer capcaity
bool ensure_lbuf_capacity(MHD_Connection& c, size_t min_needed) {
  if (!c.daemon) {
    return false;
  }

  if (c.rq.cntn.lbuf.data && c.rq.cntn.lbuf.size >= min_needed) {
    return true;
  }
  size_t have = c.rq.cntn.lbuf.size;
  size_t need = (min_needed > have) ? (min_needed - have) : 0;
  if (need) {
    mhd_daemon_extend_lbuf_up_to(c.daemon, need, &c.rq.cntn.lbuf);
  }
  return (c.rq.cntn.lbuf.data != nullptr) && (c.rq.cntn.lbuf.size >= min_needed);
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

// Dummy request callback function
static const struct MHD_Action*
dummy_request_cb(void* cls,
                 struct MHD_Request* request,
                 const struct MHD_String* path,
                 enum MHD_HTTP_Method method,
                 uint_fast64_t upload_size) {
  return nullptr;
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

  // Safe guard for buffer space
  if (fdp.ConsumeBool()) {
    const size_t clamp = fdp.ConsumeIntegralInRange<size_t>(64, 512);
    if (d.req_cfg.large_buf.space_left > clamp)
      d.req_cfg.large_buf.space_left = clamp;
  }

  // Configure connection request and general settings
  c.discard_request = false;
  c.suspended = false;
  c.connection_timeout_ms = fdp.ConsumeIntegralInRange<uint32_t>(0, 4096);
  c.last_activity = 0;

  // Add dummy callback function
  d.req_cfg.cb = dummy_request_cb;
  d.req_cfg.cb_cls = nullptr;
}

void init_connection_buffer(FuzzedDataProvider& fdp, MHD_Connection& c) {
  // Prepare connection buffer in memory pool
  size_t required = 0;
  const size_t capacity = fdp.ConsumeIntegralInRange<size_t>(512, 16384);
  char* buf = static_cast<char*>(mhd_pool_try_alloc(c.pool, capacity, &required));
  if (!buf) {
    c.read_buffer = nullptr;
    c.read_buffer_size = 0;
    c.read_buffer_offset = 0;
    return;
  }

  // Randomly choose configuration
  std::string hdrs;
  const std::string method = pick_method(fdp);
  const std::string version = pick_http_version(fdp);
  const std::string target  = (method == "*") ? "*" : (fdp.ConsumeBool() ? "/upload" : "/x?y=z");

  // Randomly break line endings in request line
  const bool bare_lf = fdp.ConsumeBool();
  const bool bare_cr = (!bare_lf) && fdp.ConsumeBool();
  auto EOL = [&](bool final=false) {
    if (bare_lf) {
      return std::string("\n");
    }
    if (bare_cr) {
      return std::string("\r");
    }

    return std::string("\r\n");
  };
  std::string req = method + " " + target + " " + version + EOL();

  // Host headers
  int host_count = 0;
  if (version == "HTTP/1.1") {
    host_count = fdp.ConsumeIntegralInRange<int>(0,2);
   } else {
    host_count = fdp.ConsumeIntegralInRange<int>(0,1);
   }

  for (int i = 0; i < host_count; ++i) {
    if (fdp.ConsumeBool()) {
      hdrs += " Host: fuzz" + std::to_string(i) + EOL();
    } else if (fdp.ConsumeBool()) {
      hdrs += "Host : fuzz" + std::to_string(i) + EOL();
    } else {
      hdrs += "Host: fuzz" + std::to_string(i) + EOL();
    }
  }

  // Transfer-Encoding and Content-Length headers
  const bool add_te = fdp.ConsumeBool();
  const bool add_cl = fdp.ConsumeBool();
  std::string te_val = fdp.PickValueInArray({"chunked","gzip","br","compress"});
  if (add_te) {
    hdrs += "Transfer-Encoding: " + te_val + EOL();
  }
  if (add_cl) {
    std::string cl;
    switch (fdp.ConsumeIntegralInRange<int>(0,3)) {
      case 0: cl = "0"; break;
      case 1: cl = std::to_string(fdp.ConsumeIntegralInRange<uint32_t>(0, 1<<20));
              break;
      case 2: cl = "18446744073709551616"; break;
      default: cl = "xyz"; break;
    }
    hdrs += "Content-Length: " + cl + EOL();
  }

  // Random minimum headers
  if (fdp.ConsumeBool()) {
    hdrs += (fdp.ConsumeBool() ? "Expect: 100-continue" : "Expect: something-weird") + EOL();
  }

  bool detect_mpart = false;
  switch (c.rq.app_act.head_act.data.post_parse.enc) {
    case MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA:
      g_mpart_boundary = "fuzz" + std::to_string(fdp.ConsumeIntegral<uint32_t>());
      hdrs += "Content-Type: multipart/form-data; boundary=" + g_mpart_boundary + EOL();
      break;
    case MHD_HTTP_POST_ENCODING_FORM_URLENCODED:
      hdrs += "Content-Type: application/x-www-form-urlencoded" + EOL();
      break;
    case MHD_HTTP_POST_ENCODING_TEXT_PLAIN:
      hdrs += "Content-Type: text/plain" + EOL();
      break;
    default: case MHD_HTTP_POST_ENCODING_OTHER:
      detect_mpart = fdp.ConsumeBool();
      if (detect_mpart) {
        g_mpart_boundary = "fuzz" + std::to_string(fdp.ConsumeIntegral<uint32_t>());
        hdrs += "Content-Type: multipart/form-data; boundary=" + g_mpart_boundary + EOL();
      } else {
        hdrs += std::string("Content-Type: ")
             + (fdp.ConsumeBool() ? "application/x-www-form-urlencoded" : "text/plain") + EOL();
      }
      break;
  }

  // Randomly add some chunked headers
  const bool add_te_chunked = fdp.ConsumeBool();
  if (add_te_chunked) {
    hdrs += "Transfer-Encoding: chunked" + EOL();
  }
  if (fdp.ConsumeBool()) {
    const uint32_t cl = fdp.ConsumeIntegralInRange<uint32_t>(0, 256);
    hdrs += "Content-Length: " + std::to_string(cl) + EOL();
  }
  if (add_te_chunked && fdp.ConsumeBool()) {
    if (fdp.ConsumeBool())
      hdrs += "Trailer: X-Fuzz-Trace" + EOL();
    else
      hdrs += "Trailer: X-One, X-Two" + EOL();
  }
  if (fdp.ConsumeBool()) {
    hdrs += (fdp.ConsumeBool() ? "Expect: 100-continue" : "Expect: something-weird") + EOL();
  }

  // Connection ending line
  hdrs += "Connection: close" + EOL();
  std::string end = EOL() + EOL();

  // Write into the read buffer
  std::string full = req + hdrs + end;
  const size_t n = (full.size() <= capacity) ? full.size() : capacity;
  memcpy(buf, full.data(), n);

  c.read_buffer = buf;
  c.read_buffer_size = capacity;
  c.read_buffer_offset = n;
}

void init_parsing_configuration(FuzzedDataProvider& fdp, MHD_Connection& c) {
  MHD_HTTP_PostEncoding enc;

  // Configure connection encoding abd methods
  if (fdp.ConsumeBool()) {
    c.rq.app_act.head_act.act = mhd_ACTION_POST_PARSE;
  } else {
    c.rq.app_act.head_act.act = mhd_ACTION_NO_ACTION;
  }
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
    mhd_stream_add_field(&connection.h1_stream, MHD_VK_HEADER, &name, &value);
  };
  add_hdr("Host", "fuzz");
  if ((size & 3u) == 0u) {
    add_hdr("Transfer-Encoding", "chunked");
  }
  if ((size & 7u) == 0u) {
    add_hdr("Content-Length", "0");
  }

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
  if (destroy_error_response(connection)) {
    return;
  }
  if (got_line && connection.stage == mhd_HTTP_STAGE_REQ_LINE_RECEIVED) {
    mhd_stream_switch_to_rq_headers_proc(&connection);
  }
  mhd_stream_parse_request_headers(&connection);

  // Only proceed to post-parse if header parsing did not bail out
  destroy_error_response(connection);
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
    mark_post_parse_ready(connection);
  } else {
    // Try prepare the body by streaming connection buffer
    const bool want_chunked = (connection.rq.have_chunked_upload == MHD_YES);

    std::string to_feed;
    if (want_chunked) {
      auto append_chunk = [&](const char* data, size_t len) {
        char hex[32];
        const int n = snprintf(hex, sizeof(hex), "%zx", len);
        to_feed.append(hex, (size_t)n);
        if ((len & 3u) == 0u) {
          to_feed += ";ext=1";
        }
        to_feed += "\r\n";
        to_feed.append(data, len);
        to_feed += "\r\n";
      };
      if (body_size <= 32) {
        append_chunk(body.data(), body_size);
      } else {
        const size_t mid = body_size / 2;
        append_chunk(body.data(), mid);
        append_chunk(body.data() + mid, body_size - mid);
      }
      to_feed += "0\r\n";
      if (body_size & 1) {
        to_feed += "X-Fuzz-Trace: 1\r\n\r\n";
      } else {
        to_feed += "\r\n";
      }
    } else {
      // Non-chunked body is handled as is
      to_feed.assign(body.data(), body_size);
    }

    // Stage into the connection read buffer (allocate if needed).
    size_t feed_sz = to_feed.size();
    bool staged = false;
    if (connection.read_buffer && connection.read_buffer_size >= feed_sz) {
      memcpy(connection.read_buffer, to_feed.data(), feed_sz);
      connection.read_buffer_offset = feed_sz;
      staged = true;
    } else {
      size_t need = 0;
      char *nb = (char*) mhd_pool_try_alloc(connection.pool, feed_sz, &need);
      if (nb) {
        memcpy(nb, to_feed.data(), feed_sz);
        connection.read_buffer = nb;
        connection.read_buffer_size = feed_sz;
        connection.read_buffer_offset = feed_sz;
        staged = true;
      }
    }

    if (staged) {
      // Use stream body approach if success
      const size_t min_needed = body_size + 1;
      if (ensure_lbuf_capacity(connection, min_needed)) {
        // Only post parse the request if buffer is enough
        connection.stage = mhd_HTTP_STAGE_BODY_RECEIVING;
        connection.rq.have_chunked_upload = MHD_NO;
        connection.rq.cntn.cntn_size = (uint64_t) body_size;
        mhd_stream_prepare_for_post_parse(&connection);
        mhd_stream_process_request_body(&connection);
        mark_post_parse_ready(connection);
      } else {
        // Fall back if not enough buffer
        size_t tmp = body_size;
        mhd_stream_prepare_for_post_parse(&connection);
        mhd_stream_post_parse(&connection, &tmp, body.data());
        mark_post_parse_ready(connection);
      }
    } else {
      // Use post prase approach if stream body failed
      mhd_stream_prepare_for_post_parse(&connection);
      mhd_stream_post_parse(&connection, &body_size, &body[0]);
      mark_post_parse_ready(connection);
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

  // Clean post parse body status
  clear_post_parse_ready(connection);
}
