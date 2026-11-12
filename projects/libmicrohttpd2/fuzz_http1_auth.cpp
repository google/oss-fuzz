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
//
// End-to-end HTTP/1.x fuzzer focused on HTTP authentication
// (src/mhd2/auth_digest.c, auth_basic.c, request_auth_get.c) and the
// connection/event-processing layer (daemon_add_conn.c, events_process.c,
// conn_data_recv.c, conn_data_send.c, stream_process_reply.c).
//
// Threat model: a remote, unauthenticated client sends arbitrary bytes over a
// TCP connection.  The "Authorization" header (RFC 7616 Digest / RFC 7617
// Basic) is parsed by MHD before any credential is known to be valid, so its
// parser, the username/userhash/extended-notation decoders and the nonce /
// nonce-count bookkeeping are pre-authentication attack surface.
//
// The raw fuzz input is written into a real MHD daemon connection (see the
// driver below).  To let the fuzzer get past the server-nonce check and reach
// the URI/argument matching and response-hash code, the harness first
// obtains a genuine nonce: if the input contains the token "@NONCE@", an
// unauthenticated request for /auth is sent first, the nonce is extracted
// from the 401 WWW-Authenticate challenge (exactly as a real client does),
// and every "@NONCE@" in the input is replaced with it.

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>

#include "microhttpd2.h"

// Realm/credentials known to the fuzz application (also in the dictionary).
#define FUZZ_REALM "fuzzrealm"
#define FUZZ_USER "fuzzuser"
#define FUZZ_PASS "fuzzpass"

namespace {

// A TCP client connection to the fuzz daemon.
class FuzzClient {
 public:
  explicit FuzzClient(struct MHD_Daemon *d);
  ~FuzzClient();
  bool ok() const { return fd_ >= 0; }

  // Write @a data to the server (as much as fits), driving the daemon so it
  // keeps draining its receive side; all server output is appended to
  // response().
  void Send(const uint8_t *data, size_t size);
  // Run the daemon event loop a few rounds, collecting output.
  void Pump(unsigned rounds);
  // Close client side and run the daemon until the connection is gone.
  void Close();

  const std::string &response() const { return resp_; }
  void ClearResponse() { resp_.clear(); }

 private:
  void Drain();
  struct MHD_Daemon *d_;
  int fd_;
  std::string resp_;
};

// ---- End-to-end driver
//
// A single MHD daemon is started in MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL mode,
// listening on 127.0.0.1 (kernel-assigned port).  Each fuzz iteration
// connects a new TCP client, lets MHD accept() it and writes the attacker
// bytes into the client end; the client is closed with an RST.  The daemon is
// driven by a tiny zero-timeout poll() loop feeding MHD_daemon_event_update()
// and MHD_daemon_process_reg_events(), so everything runs single-threaded and
// deterministically: socket recv -> HTTP/1.x or HTTP/2 layer -> request
// parsing -> application callback -> reply -> socket send.
//
// NOTE: the same driver is duplicated in fuzz_h2_conn.cpp and
// fuzz_http1_auth.cpp; keep the two copies in sync.

struct MHD_Daemon *g_daemon = nullptr;
bool g_daemon_tried = false;
struct sockaddr_in g_listen_addr;

volatile uint8_t g_sink;  // Prevents the compiler from dropping reads.

void TouchBytes(const char *p, size_t len) {
  uint8_t acc = 0;
  if (p == nullptr)
    return;
  for (size_t i = 0; i < len; ++i)
    acc ^= static_cast<uint8_t>(p[i]);
  g_sink = acc;
}

void SilentLog(void *, enum MHD_StatusCode, const char *, va_list) {}

// ---- Minimal level-triggered external event loop
// (MHD_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL), driven with zero-timeout poll().

struct WatchedFd {
  enum MHD_FdState watch_for;
  struct MHD_EventUpdateContext *ecb;
};
std::map<MHD_Socket, WatchedFd> g_watched;
int g_app_cntx_marker;  // Address used as the non-NULL application context.

void *SocketRegCb(void *, MHD_Socket fd, enum MHD_FdState watch_for,
                  void *, struct MHD_EventUpdateContext *ecb) {
  if (MHD_FD_STATE_NONE == watch_for) {
    g_watched.erase(fd);
    return nullptr;
  }
  g_watched[fd] = WatchedFd{watch_for, ecb};
  return &g_app_cntx_marker;
}

void RunEventLoopOnce(struct MHD_Daemon *d) {
  std::vector<struct pollfd> pfds;
  std::vector<WatchedFd> regs;
  pfds.reserve(g_watched.size());
  regs.reserve(g_watched.size());
  for (const auto &it : g_watched) {
    struct pollfd p;
    p.fd = it.first;
    p.events = 0;
    if (MHD_FD_STATE_IS_SET_RECV(it.second.watch_for))
      p.events |= POLLIN;
    if (MHD_FD_STATE_IS_SET_SEND(it.second.watch_for))
      p.events |= POLLOUT;
    p.revents = 0;
    pfds.push_back(p);
    regs.push_back(it.second);
  }
  if (!pfds.empty())
    (void)poll(pfds.data(), pfds.size(), 0);
  for (size_t i = 0; i < pfds.size(); ++i) {
    unsigned int st = MHD_FD_STATE_NONE;
    // A peer hang-up is reported as "readable" so that recv() returns 0.
    if (pfds[i].revents & (POLLIN | POLLHUP))
      st |= MHD_FD_STATE_RECV;
    if (pfds[i].revents & POLLOUT)
      st |= MHD_FD_STATE_SEND;
    if (pfds[i].revents & (POLLERR | POLLNVAL))
      st |= MHD_FD_STATE_EXCEPT;
    MHD_daemon_event_update(d, regs[i].ecb, static_cast<enum MHD_FdState>(st));
  }
  (void)MHD_daemon_process_reg_events(d, nullptr);
}

bool PathStartsWith(const struct MHD_String *path, const char *prefix) {
  const size_t plen = strlen(prefix);
  return path->len >= plen && 0 == memcmp(path->cstr, prefix, plen);
}

// ---- Request inspection: what a typical application reads from a request.

enum MHD_Bool ValueIter(void *, enum MHD_ValueKind,
                        const struct MHD_NameAndValue *nv) {
  TouchBytes(nv->name.cstr, nv->name.len);
  TouchBytes(nv->value.cstr, nv->value.len);
  return MHD_YES;
}

void InspectRequest(struct MHD_Request *request) {
  struct MHD_StringNullable v;
  (void)MHD_request_get_values_cb(
      request,
      static_cast<enum MHD_ValueKind>(MHD_VK_HEADER | MHD_VK_COOKIE |
                                      MHD_VK_URI_QUERY_PARAM),
      &ValueIter, nullptr);
  if (MHD_YES == MHD_request_get_value(request, MHD_VK_HEADER,
                                       MHD_HTTP_HEADER_HOST, &v))
    TouchBytes(v.cstr, v.len);
  if (MHD_YES == MHD_request_get_value(request, MHD_VK_HEADER,
                                       MHD_HTTP_HEADER_CONTENT_TYPE, &v))
    TouchBytes(v.cstr, v.len);
  if (MHD_YES == MHD_request_get_value(request, MHD_VK_COOKIE, "session", &v))
    TouchBytes(v.cstr, v.len);
  if (MHD_YES ==
      MHD_request_get_value(request, MHD_VK_URI_QUERY_PARAM, "q", &v))
    TouchBytes(v.cstr, v.len);

  union MHD_RequestInfoDynamicData dyn;
  static const enum MHD_RequestInfoDynamicType kDyn[] = {
      MHD_REQUEST_INFO_DYNAMIC_HTTP_METHOD_STRING,
      MHD_REQUEST_INFO_DYNAMIC_URI,
      MHD_REQUEST_INFO_DYNAMIC_NUMBER_URI_PARAMS,
      MHD_REQUEST_INFO_DYNAMIC_NUMBER_COOKIES,
      MHD_REQUEST_INFO_DYNAMIC_HEADER_SIZE,
      MHD_REQUEST_INFO_DYNAMIC_UPLOAD_PRESENT,
      MHD_REQUEST_INFO_DYNAMIC_UPLOAD_CHUNKED,
      MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TOTAL,
  };
  for (enum MHD_RequestInfoDynamicType t : kDyn)
    (void)MHD_request_get_info_dynamic(request, t, &dyn);

  union MHD_RequestInfoFixedData fix;
  (void)MHD_request_get_info_fixed(request, MHD_REQUEST_INFO_FIXED_HTTP_VER,
                                   &fix);
}

// ---- Responses

const struct MHD_Action *RespondText(struct MHD_Request *request,
                                     enum MHD_HTTP_StatusCode sc,
                                     const char *text) {
  struct MHD_Response *r =
      MHD_response_from_buffer_static(sc, strlen(text), text);
  if (r == nullptr)
    return MHD_action_abort_request(request);
  (void)MHD_response_add_header(r, MHD_HTTP_HEADER_CONTENT_TYPE,
                                "text/plain");
  (void)MHD_response_add_header(r, "X-Fuzz", "1");
  return MHD_action_from_response(request, r);
}

const struct MHD_UploadAction *UploadRespond(struct MHD_Request *request) {
  static const char kOk[] = "upload ok";
  struct MHD_Response *r = MHD_response_from_buffer_static(
      MHD_HTTP_STATUS_OK, sizeof(kOk) - 1, kOk);
  if (r == nullptr)
    return MHD_upload_action_abort_request(request);
  return MHD_upload_action_from_response(request, r);
}

const struct MHD_UploadAction *UploadFull(void *, struct MHD_Request *request,
                                          size_t size, void *data) {
  TouchBytes(static_cast<const char *>(data), size);
  return UploadRespond(request);
}

const struct MHD_UploadAction *UploadInc(void *, struct MHD_Request *request,
                                         size_t size, void *data) {
  if (size != 0) {
    TouchBytes(static_cast<const char *>(data), size);
    return MHD_upload_action_continue(request);
  }
  return UploadRespond(request);
}

const struct MHD_UploadAction *PostReader(
    struct MHD_Request *request, void *, const struct MHD_String *name,
    const struct MHD_StringNullable *filename,
    const struct MHD_StringNullable *content_type,
    const struct MHD_StringNullable *encoding, size_t size, const void *data,
    uint_fast64_t, enum MHD_Bool) {
  TouchBytes(name->cstr, name->len);
  TouchBytes(filename->cstr, filename->len);
  TouchBytes(content_type->cstr, content_type->len);
  TouchBytes(encoding->cstr, encoding->len);
  TouchBytes(static_cast<const char *>(data), size);
  return MHD_upload_action_continue(request);
}

const struct MHD_UploadAction *PostDone(struct MHD_Request *request, void *,
                                        enum MHD_PostParseResult) {
  return UploadRespond(request);
}

// Digest / Basic authentication, as done by a typical protected resource.
const struct MHD_Action *HandleAuth(struct MHD_Request *request) {
  union MHD_RequestInfoDynamicData dyn;

  if (MHD_SC_OK ==
      MHD_request_get_info_dynamic(
          request, MHD_REQUEST_INFO_DYNAMIC_AUTH_BASIC_CREDS, &dyn)) {
    const struct MHD_AuthBasicCreds *bc = dyn.v_auth_basic_creds;
    TouchBytes(bc->username.cstr, bc->username.len);
    TouchBytes(bc->password.cstr, bc->password.len);
    if (bc->username.len == strlen(FUZZ_USER) &&
        0 == memcmp(bc->username.cstr, FUZZ_USER, bc->username.len) &&
        bc->password.cstr != nullptr &&
        bc->password.len == strlen(FUZZ_PASS) &&
        0 == memcmp(bc->password.cstr, FUZZ_PASS, bc->password.len))
      return RespondText(request, MHD_HTTP_STATUS_OK, "basic ok");
  }

  bool stale = false;
  if (MHD_SC_OK ==
      MHD_request_get_info_dynamic(
          request, MHD_REQUEST_INFO_DYNAMIC_AUTH_DIGEST_INFO, &dyn)) {
    const struct MHD_AuthDigestInfo *di = dyn.v_auth_digest_info;
    TouchBytes(di->username.cstr, di->username.len);
    TouchBytes(di->realm.cstr, di->realm.len);
    TouchBytes(di->opaque.cstr, di->opaque.len);
    TouchBytes(di->userhash_hex.cstr, di->userhash_hex.len);
    TouchBytes(reinterpret_cast<const char *>(di->userhash_bin),
               di->userhash_bin_size);

    enum MHD_DigestAuthResult res = MHD_digest_auth_check(
        request, FUZZ_REALM, FUZZ_USER, FUZZ_PASS, 0,
        MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT, MHD_DIGEST_AUTH_MULT_ALGO_ANY);
    if (MHD_DAUTH_OK == res)
      return RespondText(request, MHD_HTTP_STATUS_OK, "digest ok");
    stale = (MHD_DAUTH_NONCE_STALE == res);

    // Same check through the pre-computed "userdigest" API (SHA-256).
    uint8_t ud[MHD_SHA256_DIGEST_SIZE];
    if (MHD_SC_OK == MHD_digest_auth_calc_userdigest(
                         MHD_DIGEST_AUTH_ALGO_SHA256, FUZZ_USER, FUZZ_REALM,
                         FUZZ_PASS, sizeof(ud), ud)) {
      if (MHD_DAUTH_OK ==
          MHD_digest_auth_check_digest(
              request, FUZZ_REALM, FUZZ_USER, sizeof(ud), ud, 0,
              MHD_DIGEST_AUTH_MULT_QOP_AUTH_ANY,
              MHD_DIGEST_AUTH_MULT_ALGO_SHA256_ANY))
        return RespondText(request, MHD_HTTP_STATUS_OK, "digest ok");
    }
  }

  static const char kDenied[] = "denied";
  struct MHD_Response *r = MHD_response_from_buffer_static(
      MHD_HTTP_STATUS_UNAUTHORIZED, sizeof(kDenied) - 1, kDenied);
  if (r == nullptr)
    return MHD_action_abort_request(request);
  (void)MHD_response_add_auth_basic_challenge(r, FUZZ_REALM, MHD_YES);
  return MHD_action_digest_auth_challenge(
      request, FUZZ_REALM, "fuzzopaque", "/", stale ? MHD_YES : MHD_NO,
      MHD_DIGEST_AUTH_MULT_QOP_AUTH, MHD_DIGEST_AUTH_MULT_ALGO_ANY_NON_SESSION,
      MHD_YES, MHD_YES, r, MHD_NO);
}

// The application.  Behaviour is selected by the (attacker supplied) path,
// as real applications route on the path.
const struct MHD_Action *RequestCb(void *, struct MHD_Request *request,
                                   const struct MHD_String *path,
                                   enum MHD_HTTP_Method method,
                                   uint_fast64_t) {
  InspectRequest(request);

  if (method == MHD_HTTP_METHOD_POST || method == MHD_HTTP_METHOD_PUT) {
    if (PathStartsWith(path, "/form"))
      return MHD_action_parse_post(request, 512, 256,
                                   MHD_HTTP_POST_ENCODING_OTHER, &PostReader,
                                   nullptr, &PostDone, nullptr);
    if (PathStartsWith(path, "/inc"))
      return MHD_action_process_upload(request, 0, nullptr, nullptr,
                                       &UploadInc, nullptr);
    return MHD_action_process_upload(request, 1024, &UploadFull, nullptr,
                                     &UploadInc, nullptr);
  }
  if (PathStartsWith(path, "/auth"))
    return HandleAuth(request);
  return RespondText(request, MHD_HTTP_STATUS_OK, "hello");
}

struct MHD_Daemon *fuzz_get_daemon() {
  if (g_daemon_tried)
    return g_daemon;
  g_daemon_tried = true;

  signal(SIGPIPE, SIG_IGN);

  // Listen on 127.0.0.1 with a kernel-assigned port (unique per fuzzing
  // process, so parallel jobs do not collide).  The socket is created here
  // and handed to MHD; MHD accept()s the client connections itself.
  // (MHD_daemon_add_connection() cannot be used: externally added sockets
  // are rejected with MHD_SC_FEATURE_DISABLED by the current library.)
  int lfd = socket(AF_INET, SOCK_STREAM, 0);
  if (lfd < 0)
    return nullptr;
  memset(&g_listen_addr, 0, sizeof(g_listen_addr));
  g_listen_addr.sin_family = AF_INET;
  g_listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  g_listen_addr.sin_port = 0;
  socklen_t alen = sizeof(g_listen_addr);
  if (0 != bind(lfd, reinterpret_cast<struct sockaddr *>(&g_listen_addr),
                sizeof(g_listen_addr)) ||
      0 != listen(lfd, 64) ||
      0 != getsockname(lfd, reinterpret_cast<struct sockaddr *>(&g_listen_addr),
                       &alen)) {
    close(lfd);
    return nullptr;
  }

  struct MHD_Daemon *d = MHD_daemon_create(&RequestCb, nullptr);
  if (d == nullptr) {
    close(lfd);
    return nullptr;
  }

  // Fixed entropy: nonces are derived deterministically from it.
  static uint8_t entropy[32];
  for (size_t i = 0; i < sizeof(entropy); ++i)
    entropy[i] = static_cast<uint8_t>(0x5A ^ (i * 31));

  if (MHD_SC_OK !=
          MHD_DAEMON_SET_OPTIONS(
              d,
              MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL(&SocketRegCb,
                                                           nullptr),
              MHD_D_OPTION_LISTEN_SOCKET(lfd),
              MHD_D_OPTION_LOG_CALLBACK(&SilentLog, nullptr),
              MHD_D_OPTION_RANDOM_ENTROPY(sizeof(entropy), entropy),
              MHD_D_OPTION_SUPPRESS_DATE_HEADER(MHD_YES),
              MHD_D_OPTION_AUTH_DIGEST_NONCE_TIMEOUT(3600),
              MHD_D_OPTION_CONN_MEMORY_LIMIT(32 * 1024)) ||
      MHD_SC_OK != MHD_daemon_start(d)) {
    MHD_daemon_destroy(d);
    return nullptr;
  }
  g_daemon = d;
  return g_daemon;
}

FuzzClient::FuzzClient(struct MHD_Daemon *d) : d_(d), fd_(-1) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return;
  // Loopback connect() completes immediately (the kernel finishes the
  // handshake; MHD accept()s from the backlog below).
  if (0 != connect(fd, reinterpret_cast<struct sockaddr *>(&g_listen_addr),
                   sizeof(g_listen_addr))) {
    close(fd);
    return;
  }
  int one = 1;
  (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  int fl = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  fd_ = fd;
  // Let MHD accept() the new connection.
  for (unsigned i = 0; i < 16; ++i) {
    RunEventLoopOnce(d_);
    union MHD_DaemonInfoDynamicData info;
    if (MHD_SC_OK == MHD_daemon_get_info_dynamic(
                         d_, MHD_DAEMON_INFO_DYNAMIC_HAS_CONNECTIONS, &info) &&
        MHD_YES == info.v_has_connections_bool)
      break;
  }
}

FuzzClient::~FuzzClient() { Close(); }

void FuzzClient::Drain() {
  if (fd_ < 0)
    return;
  char buf[4096];
  for (;;) {
    ssize_t n = recv(fd_, buf, sizeof(buf), 0);
    if (n <= 0)
      break;
    // Bound memory use: only the beginning of the output is of interest.
    if (resp_.size() < 65536)
      resp_.append(buf, static_cast<size_t>(n));
  }
}

void FuzzClient::Pump(unsigned rounds) {
  for (unsigned i = 0; i < rounds; ++i) {
    RunEventLoopOnce(d_);
    Drain();
  }
}

void FuzzClient::Send(const uint8_t *data, size_t size) {
  if (fd_ < 0)
    return;
  size_t off = 0;
  unsigned stalls = 0;
  while (off < size && stalls < 64) {
    ssize_t n = send(fd_, data + off, size - off, MSG_NOSIGNAL);
    if (n > 0) {
      off += static_cast<size_t>(n);
      stalls = 0;
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
               errno != EINTR) {
      break;  // Server closed the connection.
    } else {
      ++stalls;
    }
    Pump(1);
  }
  Pump(4);
}

void FuzzClient::Close() {
  if (fd_ < 0)
    return;
  Pump(2);
  // Abortive close (RST) to avoid TIME_WAIT port exhaustion.
  struct linger lg;
  lg.l_onoff = 1;
  lg.l_linger = 0;
  (void)setsockopt(fd_, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
  close(fd_);
  fd_ = -1;
  // Let MHD notice the EOF and clean the connection up, so that no state is
  // carried over to the next fuzz iteration.
  for (unsigned i = 0; i < 64; ++i) {
    RunEventLoopOnce(d_);
    union MHD_DaemonInfoDynamicData info;
    if (MHD_SC_OK == MHD_daemon_get_info_dynamic(
                         d_, MHD_DAEMON_INFO_DYNAMIC_HAS_CONNECTIONS, &info) &&
        MHD_NO == info.v_has_connections_bool)
      break;
  }
}

}  // namespace

static const char kToken[] = "@NONCE@";

static std::string ExtractNonce(const std::string &resp) {
  static const char kKey[] = "nonce=\"";
  size_t p = resp.find(kKey);
  if (p == std::string::npos)
    return std::string();
  p += sizeof(kKey) - 1;
  size_t e = resp.find('"', p);
  if (e == std::string::npos)
    return std::string();
  return resp.substr(p, e - p);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct MHD_Daemon *d = fuzz_get_daemon();
  if (d == nullptr)
    return 0;

  std::string input(reinterpret_cast<const char *>(data), size);

  FuzzClient client(d);
  if (!client.ok())
    return 0;

  if (input.find(kToken) != std::string::npos) {
    static const char kPrime[] =
        "GET /auth HTTP/1.1\r\nHost: fuzz\r\n\r\n";
    client.Send(reinterpret_cast<const uint8_t *>(kPrime), sizeof(kPrime) - 1);
    const std::string nonce = ExtractNonce(client.response());
    client.ClearResponse();
    size_t pos = 0;
    while ((pos = input.find(kToken, pos)) != std::string::npos) {
      input.replace(pos, sizeof(kToken) - 1, nonce);
      pos += nonce.size();
    }
  }

  if (!input.empty())
    client.Send(reinterpret_cast<const uint8_t *>(input.data()), input.size());
  client.Close();
  return 0;
}
