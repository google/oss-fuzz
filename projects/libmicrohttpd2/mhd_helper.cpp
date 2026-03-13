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
#include "mhd_helper.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

std::unique_ptr<FuzzedDataProvider> g_fdp;
std::mutex g_fdp_mu;

std::string b64encode(const std::string &in) {
  static const char* tbl =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  size_t i = 0;
  while (i + 2 < in.size()) {
    unsigned v = (unsigned((unsigned char)in[i]) << 16) |
                 (unsigned((unsigned char)in[i+1]) << 8) |
                 (unsigned((unsigned char)in[i+2]));
    out.push_back(tbl[(v >> 18) & 63]);
    out.push_back(tbl[(v >> 12) & 63]);
    out.push_back(tbl[(v >> 6) & 63]);
    out.push_back(tbl[(v) & 63]);
    i += 3;
  }
  if (i + 1 == in.size()) {
    unsigned v = (unsigned((unsigned char)in[i]) << 16);
    out.push_back(tbl[(v >> 18) & 63]);
    out.push_back(tbl[(v >> 12) & 63]);
    out.push_back('=');
    out.push_back('=');
  } else if (i + 2 == in.size()) {
    unsigned v = (unsigned((unsigned char)in[i]) << 16) |
                 (unsigned((unsigned char)in[i+1]) << 8);
    out.push_back(tbl[(v >> 18) & 63]);
    out.push_back(tbl[(v >> 12) & 63]);
    out.push_back(tbl[(v >> 6) & 63]);
    out.push_back('=');
  }
  return out;
}

enum MHD_Bool ToMhdBool(bool b) {
  return b ? MHD_YES : MHD_NO;
}

std::string safe_ascii(const std::string& in, bool allow_space) {
  std::string out; out.reserve(in.size());
  for (unsigned char c : in) {
    if (!c || c=='\r' || c=='\n' || c<32 || c>=127 || (!allow_space && c==' ')) {
      continue;
    }
    out.push_back((char)c);
  }
  if (out.empty()) {
    out = "x";
  }

  return out;
}

// Dummy functions
static enum MHD_Bool kv_cb(void*, enum MHD_ValueKind, const struct MHD_NameAndValue*) {
  return MHD_YES;
}
static enum MHD_Bool post_cb(void*, const struct MHD_PostField* pf) {
  return MHD_YES;
}

/* Start of internal helpers for sending http message to daemon through localhost socket */
static int create_socket(uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }

  // Use flag to avoid blocking on socket
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }
  struct linger lg{1, 0};
  setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

  // configure the socket to target the daemon
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  // Try connect to the daemon on the binded port in localhost
  int rc = connect(fd, (sockaddr*)&addr, sizeof(addr));
  if (rc == 0) {
    return fd;
  }

  // Early exit for invalid connection
  if (errno != EINPROGRESS) {
    close(fd);
    return -1;
  }
  pollfd p{fd, POLLOUT, 0};
  if (poll(&p, 1, 5) <= 0) {
    close(fd);
    return -1;
  }
  int err = 0;
  socklen_t elen = sizeof(err);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
    close(fd);
    return -1;
  }

  // Return the created socket
  return fd;
}

static void generate_daemon_options(const std::string& method, DaemonOpts& opts) {
  std::lock_guard<std::mutex> lk(g_fdp_mu);
  if (!g_fdp) {
    return;
  }

  // Generate general daemon options
  opts.omit_host = g_fdp->ConsumeBool();
  opts.bad_cl = g_fdp->ConsumeBool() && g_fdp->ConsumeBool();
  opts.keep_alive = g_fdp->ConsumeBool();
  opts.extra_headers = g_fdp->ConsumeBool();
  opts.use_digest = g_fdp->ConsumeBool();
  opts.send_malformed_digest = g_fdp->ConsumeBool();
  if (g_fdp->ConsumeBool()) {
    opts.realm_hint = g_fdp->ConsumeRandomLengthString(16);
    if (opts.realm_hint.empty()) opts.realm_hint = "hint";
  }

  // Generate specific daemon options with specific method
  if (!method.empty() && (method == "POST" || g_fdp->ConsumeBool())) {
    opts.te_chunked = g_fdp->ConsumeBool();
    opts.as_multipart = g_fdp->ConsumeBool();
    if (g_fdp->ConsumeBool()) {
      opts.boundary = safe_ascii(g_fdp->ConsumeRandomLengthString(24), false);
      if (opts.boundary.empty()) opts.boundary = "b";
    }
  }
}

static std::string generate_auth_header(const DaemonOpts& opts,
                                        const std::string& method,
                                        const std::string& path,
                                        const std::string& auth_user,
                                        const std::string& auth_pass,
                                        bool garble_auth) {
  // For basic auth only request
  if (!opts.use_digest) {
    if (!garble_auth) {
      std::string up = auth_user + ":" + auth_pass;
      return "Authorization: Basic " + b64encode(up) + "\r\n";
    }
    static const char* kBad[] = {
      "Authorization: Basic\r\n",
      "Authorization: Basic =\r\n",
      "Authorization: Bearer ???\r\n",
      "Authorization:\r\n"
    };
    unsigned idx = (auth_user.empty() ? 0u : (unsigned char)auth_user[0]) %
                   (unsigned)(sizeof(kBad)/sizeof(kBad[0]));
    return std::string(kBad[idx]);
  }

  // For digest auth with malformed headers
  if (!opts.send_malformed_digest) {
    std::string u = auth_user.empty() ? "user" : auth_user;
    std::string r = opts.realm_hint;
    std::string uri = (path.empty() || path[0] != '/') ? ("/" + path) : path;
    if (uri.empty()) uri = "/";
    std::string h = "Authorization: Digest ";
    h += "username=\"" + u + "\", ";
    h += "realm=\""    + r + "\", ";
    h += "nonce=\"deadbeef\", ";
    h += "uri=\""      + uri + "\", ";
    h += "response=\"00000000000000000000000000000000\", ";
    h += "opaque=\"cafebabe\", ";
    h += "qop=auth, ";
    h += "nc=00000001, cnonce=\"0123456789abcdef\"\r\n";
    return h;
  }

  // For digest auth with correctly formatted headers with random data
  static const char* kBadDigest[] = {
    "Authorization: Digest\r\n",
    "Authorization: Digest username=\r\n",
    "Authorization: Digest realm=\"\", uri=/, response=\r\n",
    "Authorization: Digest nonce=,opaque=\r\n"
  };
  unsigned idx = (unsigned char)(auth_user.empty()?0:auth_user[0]) %
                 (unsigned)(sizeof(kBadDigest)/sizeof(kBadDigest[0]));

  return std::string(kBadDigest[idx]);
}

static void append_headers(std::string& req,
                           const DaemonOpts& opts,
                           const std::string& auth_header) {
  // Set host
  if (!opts.omit_host) {
    req += "Host: 127.0.0.1\r\n";
  }

  // Append auth headers
  req += auth_header;

  // Append general headers
  if (opts.extra_headers) {
    req += "User-Agent: fuzz\r\n";
    req += "Accept: */*\r\n";
    req += "X-Fuzz: 1\r\n";
    req += "X-Dup: a\r\nX-Dup: b\r\n";
  }
}

static std::string make_multipart(const DaemonOpts& opts,
                                  const std::string& body,
                                  std::string& content_type_line_out) {
  // Do nothing for non-multipart iteration
  if (!opts.as_multipart) {
    content_type_line_out.clear();
    return body;
  }

  // Configure the request body to be multipart format
  std::string b = opts.boundary.empty() ? "b" : opts.boundary;
  std::string mp;
  mp += "--" + b + "\r\n";
  mp += "Content-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n";
  if (!body.empty()) mp += "Content-Type: application/octet-stream\r\n";
  mp += "\r\n";
  mp += body;
  mp += "\r\n--" + b + "--\r\n";
  content_type_line_out = "Content-Type: multipart/form-data; boundary=" + b + "\r\n";

  return mp;
}


static void append_request_headers(std::string& req,
                                   const DaemonOpts& opts,
                                   size_t payload_size,
                                   const std::string& content_type_line) {
  // Append content type header
  if (!content_type_line.empty()) {
    req += content_type_line;
  }
  if (payload_size == 0) {
    return;
  }

  // Append encoding and payload size headers
  if (opts.te_chunked) {
    req += "Transfer-Encoding: chunked\r\n";
  } else {
    if (!opts.bad_cl) {
      req += "Content-Length: " + std::to_string(payload_size) + "\r\n";
    } else {
      req += "Content-Length: " + std::to_string(payload_size + 5) + "\r\n";
    }
  }

  // Append connection lifeline header
  req += opts.keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
}

static void append_chunked_payload(std::string& req, const std::string& payload) {
  // End the request body gracefully for empty payload
  if (payload.empty()) {
    req += "0\r\n\r\n";
    return;
  }

  // Continue to write all the body data chunk by chunk to the request
  size_t off = 0;
  while (off < payload.size()) {
    char szbuf[32];

    size_t remain = payload.size() - off;
    size_t chunk = std::min(remain > 1 ? remain / 2 : 1, size_t(4096));

    int n = snprintf(szbuf, sizeof(szbuf), "%zx\r\n", chunk);
    if (n > 0) {
      req.append(szbuf, (size_t)n);
    }
    req.append(payload.data() + off, chunk);
    req += "\r\n";
    off += chunk;
  }
  req += "0\r\n\r\n";
}


static void send_request(int fd, const std::string& req) {
  // Configure sent parameters and max timeout
  size_t off = 0;
  const int kSendStepMs = 2;
  const int kSendMaxMs = 8;
  int waited = 0;

  // Continue to send data though the socket until all data is sent or timeout is reached
  while (off < req.size()) {
    ssize_t s = send(fd, req.data() + off, req.size() - off, 0);
    if (s > 0) {
      off += (size_t)s;
      continue;
    }

    if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      pollfd p{fd, POLLOUT, 0};
      if (poll(&p, 1, kSendStepMs) <= 0) {
        waited += kSendStepMs;
        if (waited >= kSendMaxMs) {
          break;
        }
      }
      continue;
    }
    break;
  }

  shutdown(fd, SHUT_WR);
}

static void wait_for_response(int fd) {
  // Configure response waiting parameters and timeout
  static const int kStepMs = 2;
  static const int kMaxMs = 8;
  static const size_t kMaxRead = 64 * 1024;
  int waited = 0;
  size_t total = 0;

  // Continue to receive data from daemon throug the socket until max data threshold or timeout is reached
  while (true) {
    pollfd p{fd, POLLIN, 0};
    int pr = poll(&p, 1, kStepMs);
    if (pr <= 0) {
      waited += kStepMs;
      if (waited >= kMaxMs) {
        break;
      }

      continue;
    }

    char buf[1024];
    ssize_t r = recv(fd, buf, sizeof(buf), 0);
    if (r > 0) {
      total += (size_t)r;
      if (total >= kMaxRead) break;
      continue;
    }
    if (r == 0) {
      break;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      continue;
    }

    break;
  }
}
/* End of internal helpers for sending http message to daemon through localhost socket */

void send_http_request_blocking(uint16_t port,
                                const std::string& method,
                                const std::string& path,
                                const std::string& auth_user,
                                const std::string& auth_pass,
                                const std::string& body,
                                bool garble_auth) {
  // Create and connect to the daemon with HTTP localhost socket
  int fd = create_socket(port);
  if (fd < 0) {
    return;
  }

  // Generate options for the daemon connection and request
  DaemonOpts opts;
  generate_daemon_options(method, opts);

  // Build the request body for the random request
  std::string req;
  req.reserve(512 + body.size());
  const std::string& m = method.empty() ? std::string("GET") : method;
  req += m;
  req += " ";
  std::string full_path = (path.empty() || path[0] != '/') ? ("/" + path) : path;
  if (full_path.empty()) full_path = "/";
  req += full_path;
  req += " HTTP/1.1\r\n";

  // Generate auth headers
  std::string auth_header = generate_auth_header(opts, m, path, auth_user, auth_pass, garble_auth);

  // Append headers into the daemon request
  append_headers(req, opts, auth_header);

  // Randomly make the request with multipart data
  std::string content_type_line;
  std::string payload = make_multipart(opts, body, content_type_line);

  // Append additional request specific headers
  append_request_headers(req, opts, payload.size(), content_type_line);
  req += "\r\n";

  // Add random body content to the request object depends on the content type chosen
  if (opts.te_chunked) {
    append_chunked_payload(req, payload);
  } else {
    req += payload;
  }

  // Sending the request to the daemon through the localhost socket
  send_request(fd, req);

  // Wait for a while for daemon response
  wait_for_response(fd);

  // Close the socket
  close(fd);
}

/* Start of internal helpers for daemon request handling */
static void generate_daemon_req_opts(DaemonReqOpts& o,
                                     enum MHD_HTTP_Method method) {
  std::lock_guard<std::mutex> lk(g_fdp_mu);
  if (!g_fdp) {
    o.realm = "realm";
    return;
  }

  // Generate basic daemon request options
  o.realm = g_fdp->ConsumeRandomLengthString(16);
  if (o.realm.empty()) {
    o.realm = "realm";
  }
  o.allowed_user = g_fdp->ConsumeRandomLengthString(12);
  o.allowed_pass = g_fdp->ConsumeRandomLengthString(12);
  o.force_challenge = g_fdp->ConsumeBool();
  o.force_bad = g_fdp->ConsumeBool();
  o.flip_ok_to_forbidden = g_fdp->ConsumeBool();
  o.prefer_utf8 = ToMhdBool(g_fdp->ConsumeBool());
  o.use_digest = g_fdp->ConsumeBool();

  o.qop  = g_fdp->ConsumeBool() ? MHD_DIGEST_AUTH_MULT_QOP_AUTH
                                : MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT;
  o.algo = g_fdp->ConsumeBool() ? MHD_DIGEST_AUTH_MULT_ALGO_ANY
                                : MHD_DIGEST_AUTH_MULT_ALGO_MD5;

  o.send_stale = g_fdp->ConsumeBool() ? MHD_YES : MHD_NO;
  o.allow_userhash = g_fdp->ConsumeBool() ? MHD_YES : MHD_NO;
  o.use_opaque = g_fdp->ConsumeBool();

  // Generate daemon request options for form encoded request
  o.buf_sz = 64 + g_fdp->ConsumeIntegralInRange<size_t>(0, 8192);
  o.max_nonstream = g_fdp->ConsumeIntegralInRange<size_t>(0, 64 * 1024);
  o.enc = g_fdp->PickValueInArray<enum MHD_HTTP_PostEncoding>({
    MHD_HTTP_POST_ENCODING_FORM_URLENCODED,
    MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA,
    MHD_HTTP_POST_ENCODING_TEXT_PLAIN,
    MHD_HTTP_POST_ENCODING_OTHER
  });
  o.do_parse_post = g_fdp->ConsumeBool() || (method == MHD_HTTP_METHOD_POST);
  o.do_process_upload = g_fdp->ConsumeBool();
}

static const struct MHD_UploadAction*
post_done_cb(struct MHD_Request *req, void *cls, enum MHD_PostParseResult pr) {
  return MHD_upload_action_continue(req);
}

static const struct MHD_UploadAction*
post_reader(struct MHD_Request *req,
            void *cls,
            const struct MHD_String *name,
            const struct MHD_StringNullable *filename,
            const struct MHD_StringNullable *content_type,
            const struct MHD_StringNullable *encoding,
            size_t size,
            const void *data,
            uint_fast64_t off,
            enum MHD_Bool final_data) {
  return MHD_upload_action_continue(req);
}

static const struct MHD_UploadAction*
upload_cb(void *upload_cls,
          struct MHD_Request *request,
          size_t content_data_size,
          void *content_data) {
  enum MHD_HTTP_StatusCode sc = content_data_size ? MHD_HTTP_STATUS_OK : MHD_HTTP_STATUS_NO_CONTENT;
  struct MHD_Response *r = MHD_response_from_empty(sc);
  if (!r) {
    return NULL;
  }

  return MHD_upload_action_from_response(request, r);
}

static const struct MHD_Action* request_parsing(struct MHD_Request* request, const DaemonReqOpts& o) {
  // Handle parsing of post request with form data or general parameters
  if (o.do_parse_post) {
    const struct MHD_Action *a =
      MHD_action_parse_post(request,
                            o.buf_sz,
                            o.max_nonstream,
                            o.enc,
                            &post_reader, nullptr,
                            &post_done_cb, nullptr);
    if (a) {
      MHD_request_get_post_data_cb(
        request,
        [](void *cls, const struct MHD_PostField *pf)->enum MHD_Bool {
          std::lock_guard<std::mutex> lk(g_fdp_mu);
          if (!g_fdp) {
            return MHD_YES;
          }
          return ToMhdBool(g_fdp->ConsumeBool());
        },
        nullptr);
      return a;
    }
  }

  // Handle parsing of upload request
  if (o.do_process_upload) {
    const struct MHD_Action *a =
      MHD_action_process_upload(request,
                                o.buf_sz,
                                &upload_cb, nullptr,
                                &upload_cb,  nullptr);
    if (a) {
      return a;
    }
  }

  return nullptr;
}

static const struct MHD_Action*
handle_basic_auth(struct MHD_Request* request,
                  const DaemonReqOpts& o) {
  union MHD_RequestInfoDynamicData req_data;
  enum MHD_StatusCode res = MHD_request_get_info_dynamic(
      request, MHD_REQUEST_INFO_DYNAMIC_AUTH_BASIC_CREDS, &req_data);

  // Send bad header response
  if (o.force_bad || (MHD_SC_REQ_AUTH_DATA_BROKEN == res)) {
    return MHD_action_from_response(
      request,
      MHD_response_from_buffer_static(
        MHD_HTTP_STATUS_BAD_REQUEST, 10, "bad_header"));
  }

  // Send unauthorized response
  if (o.force_challenge || (MHD_SC_AUTH_ABSENT == res)) {
    const char* realm_cstr = o.realm.c_str();
    return MHD_action_basic_auth_challenge_a(
      request,
      realm_cstr,
      o.prefer_utf8,
      MHD_response_from_buffer_static(
        MHD_HTTP_STATUS_UNAUTHORIZED, 4, "auth"));
  }

  // Fail safe to abort request if unknown request status is provided
  if (MHD_SC_OK != res) {
    return MHD_action_abort_request(request);
  }

  // Prepeare and perform basic auth check
  const struct MHD_AuthBasicCreds *creds = req_data.v_auth_basic_creds;
  bool user_ok = (creds->username.len == o.allowed_user.size()) &&
                 (0 == memcmp(o.allowed_user.data(),
                              creds->username.cstr,
                              creds->username.len));
  bool pass_ok = (creds->password.len == o.allowed_pass.size()) &&
                 (0 == memcmp(o.allowed_pass.data(),
                              creds->password.cstr,
                              creds->password.len));
  bool ok = user_ok && pass_ok;

  // Try randomly flip the result
  if (o.flip_ok_to_forbidden) {
    ok = false;
  }

  // Return result with status in response
  if (ok) {
    return MHD_action_from_response(
      request,
      MHD_response_from_buffer_static(
        MHD_HTTP_STATUS_OK, 2, "OK"));
  }

  return MHD_action_from_response(
    request,
    MHD_response_from_buffer_static(
      MHD_HTTP_STATUS_FORBIDDEN, 9, "FORBIDDEN"));
}

static const struct MHD_Action*
handle_digest_auth(struct MHD_Request* request,
                   const DaemonReqOpts& o) {
  union MHD_RequestInfoDynamicData req_data;
  enum MHD_StatusCode res = MHD_request_get_info_dynamic(
      request, MHD_REQUEST_INFO_DYNAMIC_AUTH_DIGEST_INFO, &req_data);

  const char* opaque_opt = o.use_opaque ? "opaque-token" : nullptr;

  // Early exit for missing auth in request
  if (MHD_SC_AUTH_ABSENT == res || o.force_challenge) {
    return MHD_action_digest_auth_challenge_a(
      request,
      o.realm.c_str(),
      "0",
      opaque_opt,
      o.send_stale,
      o.qop,
      o.algo,
      o.allow_userhash,
      MHD_YES,
      MHD_response_from_buffer_static(
        MHD_HTTP_STATUS_UNAUTHORIZED, 4, "auth"));
  }

  // Early exit for invalid or malformed request headers
  if (MHD_SC_REQ_AUTH_DATA_BROKEN == res || o.force_bad) {
    return MHD_action_from_response(
      request,
      MHD_response_from_buffer_static(
        MHD_HTTP_STATUS_BAD_REQUEST, 15, "Header Invalid."));
  }

  // Fail safe to abort request if unknown response status is provided
  if (MHD_SC_OK != res) {
    return MHD_action_abort_request(request);
  }

  // Prepeare and perform digest auth check
  const struct MHD_AuthDigestInfo *di = req_data.v_auth_digest_info;
  bool user_ok = (di->username.len == o.allowed_user.size()) &&
                 (0 == memcmp(o.allowed_user.data(),
                              di->username.cstr,
                              di->username.len));

  if (user_ok) {
    enum MHD_DigestAuthResult auth_res =
      MHD_digest_auth_check(request,
                            o.realm.c_str(),
                            o.allowed_user.c_str(),
                            o.allowed_pass.c_str(),
                            0,
                            o.qop,
                            o.algo);

    // Return auth result or randomly flip the result
    if (MHD_DAUTH_OK == auth_res) {
      if (!o.flip_ok_to_forbidden) {
        return MHD_action_from_response(
          request,
          MHD_response_from_buffer_static(
            MHD_HTTP_STATUS_OK, 2, "OK"));
      }
      return MHD_action_from_response(
        request,
        MHD_response_from_buffer_static(
          MHD_HTTP_STATUS_FORBIDDEN, 9, "FORBIDDEN"));
    }

    if (MHD_DAUTH_NONCE_STALE == auth_res) {
      return MHD_action_digest_auth_challenge_a(
        request,
        o.realm.c_str(),
        "0",
        opaque_opt,
        MHD_YES,
        o.qop,
        o.algo,
        o.allow_userhash,
        MHD_YES,
        MHD_response_from_buffer_static(
          MHD_HTTP_STATUS_UNAUTHORIZED, 4, "auth"));
    }

    return MHD_action_from_response(
      request,
      MHD_response_from_buffer_static(
        MHD_HTTP_STATUS_FORBIDDEN, 9, "FORBIDDEN"));
  }

  return MHD_action_from_response(
    request,
    MHD_response_from_buffer_static(
      MHD_HTTP_STATUS_FORBIDDEN, 9, "FORBIDDEN"));
}
/* End of internal helpers for daemon request handling */

MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_NONNULL_(3)
const struct MHD_Action*
req_cb(void* cls,
       struct MHD_Request* MHD_RESTRICT request,
       const struct MHD_String* MHD_RESTRICT path,
       enum MHD_HTTP_Method method,
       uint_fast64_t upload_size) {
  DaemonReqOpts opts;
  generate_daemon_req_opts(opts, method);

  // Try parinsg or streaming request
  if (const struct MHD_Action* a = request_parsing(request, opts)) {
    return a;
  }

  // Perform basic or digest auth on the request
  if (!opts.use_digest) {
    return handle_basic_auth(request, opts);
  }
  return handle_digest_auth(request, opts);
}

MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_NONNULL_(3)
const struct MHD_Action*
req_cb_stream(void*,
              struct MHD_Request* MHD_RESTRICT request,
              const struct MHD_String* MHD_RESTRICT path,
              enum MHD_HTTP_Method method,
              uint_fast64_t upload_size) {
  struct MHD_StringNullable out;

  // Fuzz MHD_request_get_value for different parameters on random request
  MHD_request_get_value(request, MHD_VK_HEADER, "host", &out);
  MHD_request_get_value(request, MHD_VK_HEADER, "content-type", &out);
  MHD_request_get_value(request, MHD_VK_COOKIE, "cookie", &out);
  MHD_request_get_value(request, MHD_VK_URI_QUERY_PARAM, "q", &out);
  MHD_request_get_values_cb(request, MHD_VK_HEADER, kv_cb, nullptr);
  MHD_request_get_values_cb(request, MHD_VK_COOKIE, kv_cb, nullptr);
  MHD_request_get_values_cb(request, MHD_VK_URI_QUERY_PARAM, kv_cb, nullptr);

  // Fuzz MHD_request_get_post_data_cb on random request
  MHD_request_get_post_data_cb(request, post_cb, nullptr);


  // Fuzz MHD_request_get_info_fixed for different parameters on random request
  union MHD_RequestInfoFixedData fix;
  MHD_request_get_info_fixed(request, MHD_REQUEST_INFO_FIXED_HTTP_VER, &fix);
  MHD_request_get_info_fixed(request, MHD_REQUEST_INFO_FIXED_HTTP_METHOD, &fix);
  MHD_request_get_info_fixed(request, MHD_REQUEST_INFO_FIXED_DAEMON, &fix);
  MHD_request_get_info_fixed(request, MHD_REQUEST_INFO_FIXED_CONNECTION, &fix);
  MHD_request_get_info_fixed(request, MHD_REQUEST_INFO_FIXED_STREAM, &fix);
  MHD_request_get_info_fixed(request, MHD_REQUEST_INFO_FIXED_APP_CONTEXT, &fix);

  // Fuzz MHD_request_get_info_dynamic for different parameters on random request
  union MHD_RequestInfoDynamicData dyn;
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_HTTP_METHOD_STRING, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_URI, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_NUMBER_URI_PARAMS, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_NUMBER_COOKIES, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_HEADER_SIZE, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_NUMBER_POST_PARAMS, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_UPLOAD_PRESENT, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_UPLOAD_CHUNKED, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TOTAL, &dyn);
  MHD_request_get_info_dynamic(request, MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_RECIEVED, &dyn);

  // Fuzz response creation from random request processing
  struct MHD_Response* resp = MHD_response_from_empty(MHD_HTTP_STATUS_NO_CONTENT);
  if (!resp) {
    return MHD_action_abort_request(request);
  }

  // Fuzz response and request abortion
  MHD_response_add_header(resp, "x-fuzz", "values");
  const struct MHD_Action* act = MHD_action_from_response(request, resp);
  MHD_response_destroy(resp);
  return act ? act : MHD_action_abort_request(request);
}

MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_NONNULL_(3)
const struct MHD_Action*
req_cb_process(void*,
               struct MHD_Request* MHD_RESTRICT request,
               const struct MHD_String* MHD_RESTRICT path,
               enum MHD_HTTP_Method method,
               uint_fast64_t upload_size) {
  // Create info unions
  union MHD_RequestInfoFixedData f;
  union MHD_RequestInfoDynamicData d;

  // Fuzz MHD_request_get_info_fixed_sz for different parameters on random request
  MHD_request_get_info_fixed_sz(request, MHD_REQUEST_INFO_FIXED_HTTP_VER, &f, sizeof(f));
  MHD_request_get_info_fixed_sz(request, MHD_REQUEST_INFO_FIXED_HTTP_METHOD, &f, sizeof(f));
  MHD_request_get_info_fixed_sz(request, MHD_REQUEST_INFO_FIXED_DAEMON, &f, sizeof(f));
  MHD_request_get_info_fixed_sz(request, MHD_REQUEST_INFO_FIXED_CONNECTION, &f, sizeof(f));
  MHD_request_get_info_fixed_sz(request, MHD_REQUEST_INFO_FIXED_STREAM, &f, sizeof(f));
  MHD_request_get_info_fixed_sz(request, MHD_REQUEST_INFO_FIXED_APP_CONTEXT, &f, sizeof(f));

  // Fuzz MHD_request_get_info_dynamic_sz for different parameters on random request
  MHD_request_get_info_dynamic_sz(request, MHD_REQUEST_INFO_DYNAMIC_HTTP_METHOD_STRING, &d, sizeof(d));
  MHD_request_get_info_dynamic_sz(request, MHD_REQUEST_INFO_DYNAMIC_URI, &d, sizeof(d));
  MHD_request_get_info_dynamic_sz(request, MHD_REQUEST_INFO_DYNAMIC_NUMBER_URI_PARAMS, &d, sizeof(d));
  MHD_request_get_info_dynamic_sz(request, MHD_REQUEST_INFO_DYNAMIC_NUMBER_COOKIES, &d, sizeof(d));
  MHD_request_get_info_dynamic_sz(request, MHD_REQUEST_INFO_DYNAMIC_HEADER_SIZE, &d, sizeof(d));
  MHD_request_get_info_dynamic_sz(request, MHD_REQUEST_INFO_DYNAMIC_AUTH_DIGEST_INFO, &d, sizeof(d));
  MHD_request_get_info_dynamic_sz(request, MHD_REQUEST_INFO_DYNAMIC_AUTH_BASIC_CREDS, &d, sizeof(d));

  {
    static const char realm[] = "fuzz-realm";
    static const char user[]  = "u";
    static const char pass[]  = "p";

    enum MHD_DigestAuthAlgo algos[] = {
      MHD_DIGEST_AUTH_ALGO_MD5,
      MHD_DIGEST_AUTH_ALGO_SHA256,
      MHD_DIGEST_AUTH_ALGO_SHA512_256
    };

    for (unsigned i = 0; i < (unsigned)(sizeof(algos)/sizeof(algos[0])); ++i) {
      size_t sz = MHD_digest_get_hash_size(algos[i]);
      if (sz == 0 || sz > 64) {
        continue;
      }
      unsigned char ha1[64];
      if (MHD_SC_OK == MHD_digest_auth_calc_userdigest(algos[i], user, realm, pass, sz, ha1)) {
        MHD_digest_auth_check_digest(
            request, realm, user, sz, ha1,
            0, MHD_DIGEST_AUTH_MULT_QOP_AUTH_ANY,
            MHD_DIGEST_AUTH_MULT_ALGO_ANY_NON_SESSION);
      }
    }
  }

  // Force OK response
  struct MHD_Response* r = MHD_response_from_empty(MHD_HTTP_STATUS_OK);
  return MHD_action_from_response(request, r);
}
