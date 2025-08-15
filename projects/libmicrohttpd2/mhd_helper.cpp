#include "mhd_helper.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#include <fuzzer/FuzzedDataProvider.h>

extern std::unique_ptr<FuzzedDataProvider> g_fdp;
extern std::mutex g_fdp_mu;

static std::string b64encode(const std::string &in) {
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

void send_http_request_blocking(uint16_t port,
                                const std::string& method,
                                const std::string& path,
                                const std::string& auth_user,
                                const std::string& auth_pass,
                                const std::string& body,
                                bool garble_auth) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return;
  }

  // Configure connection flags
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }
  struct linger lg{1, 0};
  setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  // Try connect to MHD daemon
  int rc = connect(fd, (sockaddr*)&addr, sizeof(addr));
  if (rc != 0) {
    if (errno != EINPROGRESS) {
      close(fd);
      return;
    }
    pollfd p{fd, POLLOUT, 0};
    if (poll(&p, 1, 5) <= 0) {
      close(fd);
      return;
    }
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
      close(fd);
      return;
    }
  }

  // Generate random data
  bool omit_host=false;
  bool bad_cl=false;
  bool keep_alive=false;
  bool extra_headers=false;
  bool use_digest=false;
  bool send_malformed_digest=false;
  std::string realm_hint="hint";
  {
    std::lock_guard<std::mutex> lk(g_fdp_mu);
    if (g_fdp) {
      omit_host = g_fdp->ConsumeBool();
      bad_cl = g_fdp->ConsumeBool() && g_fdp->ConsumeBool();
      keep_alive = g_fdp->ConsumeBool();
      extra_headers = g_fdp->ConsumeBool();
      use_digest = g_fdp->ConsumeBool();
      send_malformed_digest = g_fdp->ConsumeBool();
      if (g_fdp->ConsumeBool()) {
        realm_hint = g_fdp->ConsumeRandomLengthString(16);
      }
    }
  }

  // Build Authorization header, either with legit or malformed random data
  std::string auth_header;
  if (!use_digest) {
    if (!garble_auth) {
      std::string up = auth_user + ":" + auth_pass;
      auth_header = "Authorization: Basic " + b64encode(up) + "\r\n";
    } else {
      static const char* kBad[] = {
        "Authorization: Basic\r\n",
        "Authorization: Basic =\r\n",
        "Authorization: Bearer ???\r\n",
        "Authorization:\r\n"
      };
      auth_header = kBad[(auth_user.empty() ? 0 : (unsigned char)auth_user[0]) %
                         (sizeof(kBad)/sizeof(kBad[0]))];
    }
  } else {
    if (!send_malformed_digest) {
      std::string u = auth_user.empty() ? "user" : auth_user;
      std::string r = realm_hint;
      std::string uri = (path.empty() || path[0] != '/') ? ("/" + path) : path;
      if (uri.empty()) uri = "/";
      auth_header  = "Authorization: Digest ";
      auth_header += "username=\"" + u + "\", ";
      auth_header += "realm=\""    + r + "\", ";
      auth_header += "nonce=\"deadbeef\", ";
      auth_header += "uri=\""      + uri + "\", ";
      auth_header += "response=\"00000000000000000000000000000000\", ";
      auth_header += "opaque=\"cafebabe\", ";
      auth_header += "qop=auth, ";
      auth_header += "nc=00000001, cnonce=\"0123456789abcdef\"\r\n";
    } else {
      static const char* kBadDigest[] = {
        "Authorization: Digest\r\n",
        "Authorization: Digest username=\r\n",
        "Authorization: Digest realm=\"\", uri=/, response=\r\n",
        "Authorization: Digest nonce=,opaque=\r\n"
      };
      auth_header = kBadDigest[(unsigned char)(auth_user.empty()?0:auth_user[0]) %
                               (sizeof(kBadDigest)/sizeof(kBadDigest[0]))];
    }
  }

  // Build request
  std::string req;
  req.reserve(512 + body.size());
  req += method.empty() ? "GET" : method;
  req += " ";
  std::string full_path = (path.empty() || path[0] != '/') ? ("/" + path) : path;
  if (full_path.empty()) full_path = "/";
  req += full_path;
  req += " HTTP/1.1\r\n";

  if (!omit_host) req += "Host: 127.0.0.1\r\n";
  req += auth_header;

  if (extra_headers) {
    req += "User-Agent: fuzz\r\n";
    req += "Accept: */*\r\n";
    req += "X-Fuzz: 1\r\n";
    req += "X-Dup: a\r\nX-Dup: b\r\n";
  }

  if (!body.empty()) {
    if (!bad_cl) {
      req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    } else {
      req += "Content-Length: " + std::to_string(body.size() + 5) + "\r\n";
    }
  }

  req += "Connection: close\r\n";
  req += "\r\n";
  req += body;

  size_t off = 0;
  const int kSendStepMs = 2;
  const int kSendMaxMs = 8;
  int waited = 0;
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
        if (waited >= kSendMaxMs) break;
      }
      continue;
    }
    break;
  }

  // Signal request ending
  shutdown(fd, SHUT_WR);

  // Handling response
  static const int kStepMs = 2, kMaxMs = 8;
  static const size_t kMaxRead = 64 * 1024;
  waited = 0;
  size_t total = 0;
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
      if (total >= kMaxRead) {
        break;
      }
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

  close(fd);
}

MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_NONNULL_(3)
const struct MHD_Action*
req_cb(void* cls,
       struct MHD_Request* MHD_RESTRICT request,
       const struct MHD_String* MHD_RESTRICT path,
       enum MHD_HTTP_Method method,
       uint_fast64_t upload_size) {
  union MHD_RequestInfoDynamicData req_data;
  enum MHD_StatusCode res;

  std::string realm, allowed_user, allowed_pass;
  bool force_challenge = false, force_bad = false, flip_ok_to_forbidden = false;
  enum MHD_Bool prefer_utf8 = MHD_NO;

  bool use_digest = false;
  MHD_DigestAuthMultiQOP  qop  = MHD_DIGEST_AUTH_MULT_QOP_AUTH;
  MHD_DigestAuthMultiAlgo algo = MHD_DIGEST_AUTH_MULT_ALGO_ANY;

  enum MHD_Bool send_stale = MHD_NO;
  enum MHD_Bool allow_userhash = MHD_NO;
  const char* opaque_opt = NULL;

  // Generate random data for response
  {
    std::lock_guard<std::mutex> lk(g_fdp_mu);
    if (g_fdp) {
      realm = g_fdp->ConsumeRandomLengthString(16);
      allowed_user = g_fdp->ConsumeRandomLengthString(12);
      allowed_pass = g_fdp->ConsumeRandomLengthString(12);
      force_challenge = g_fdp->ConsumeBool();
      force_bad = g_fdp->ConsumeBool();
      flip_ok_to_forbidden = g_fdp->ConsumeBool();
      prefer_utf8 = g_fdp->ConsumeBool() ? MHD_YES : MHD_NO;
      use_digest = g_fdp->ConsumeBool();

      if (g_fdp->ConsumeBool()) {
        qop  = MHD_DIGEST_AUTH_MULT_QOP_AUTH;
      } else {
        qop  = MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT;
      }
      if (g_fdp->ConsumeBool()) {
        algo = MHD_DIGEST_AUTH_MULT_ALGO_ANY;
      } else {
        algo = MHD_DIGEST_AUTH_MULT_ALGO_MD5;
      }
      send_stale = g_fdp->ConsumeBool() ? MHD_YES : MHD_NO;
      allow_userhash = g_fdp->ConsumeBool() ? MHD_YES : MHD_NO;
      if (g_fdp->ConsumeBool()) {
        opaque_opt = "opaque-token";
      }
    }
  }

  if (realm.empty()) {
    realm = "realm";
  }

  // Use basic authentication for this request
  if (!use_digest) {
    res = MHD_request_get_info_dynamic(request,
                                       MHD_REQUEST_INFO_DYNAMIC_AUTH_BASIC_CREDS,
                                       &req_data);

    if (force_bad || (MHD_SC_REQ_AUTH_DATA_BROKEN == res)) {
      return MHD_action_from_response(
        request,
        MHD_response_from_buffer_static(
          MHD_HTTP_STATUS_BAD_REQUEST,
          10, "bad_header"));
    }

    if (force_challenge || (MHD_SC_AUTH_ABSENT == res)) {
      const char* realm_cstr = realm.c_str();
      return MHD_action_basic_auth_challenge_a(
        request,
        realm_cstr,
        prefer_utf8,
        MHD_response_from_buffer_static(
          MHD_HTTP_STATUS_UNAUTHORIZED,
          4, "auth"));
    }

    if (MHD_SC_OK != res) {
      return MHD_action_abort_request(request);
    }

    // copy in data for authentication
    const struct MHD_AuthBasicCreds *creds = req_data.v_auth_basic_creds;
    bool user_ok = (creds->username.len == allowed_user.size()) &&
                   (0 == memcmp(allowed_user.data(),
                                creds->username.cstr,
                                creds->username.len));
    bool pass_ok = (creds->password.len == allowed_pass.size()) &&
                   (0 == memcmp(allowed_pass.data(),
                                creds->password.cstr,
                                creds->password.len));
    bool ok = user_ok && pass_ok;

    if (flip_ok_to_forbidden) {
      ok = false;
    }

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

  // Use digest authentication for this daemon request
  res = MHD_request_get_info_dynamic(request,
                                     MHD_REQUEST_INFO_DYNAMIC_AUTH_DIGEST_INFO,
                                     &req_data);

  if (MHD_SC_AUTH_ABSENT == res || force_challenge) {
    return MHD_action_digest_auth_challenge_a(
      request,
      realm.c_str(),
      "0",
      opaque_opt,
      send_stale,
      qop,
      algo,
      allow_userhash,
      MHD_YES,
      MHD_response_from_buffer_static(
        MHD_HTTP_STATUS_UNAUTHORIZED,
        4, "auth"));
  }

  if (MHD_SC_REQ_AUTH_DATA_BROKEN == res || force_bad) {
    return MHD_action_from_response(
      request,
      MHD_response_from_buffer_static(
        MHD_HTTP_STATUS_BAD_REQUEST,
        15, "Header Invalid."));
  }

  if (MHD_SC_OK != res) {
    return MHD_action_abort_request(request);
  }

  // Prepare the digest authentication configurations and response status
  const struct MHD_AuthDigestInfo *di = req_data.v_auth_digest_info;
  bool user_ok = (di->username.len == allowed_user.size()) &&
                 (0 == memcmp(allowed_user.data(),
                              di->username.cstr,
                              di->username.len));

  if (user_ok) {
    enum MHD_DigestAuthResult auth_res =
      MHD_digest_auth_check(request,
                            realm.c_str(),
                            allowed_user.c_str(),
                            allowed_pass.c_str(),
                            0,
                            qop,
                            algo);

    if (MHD_DAUTH_OK == auth_res) {
      if (!flip_ok_to_forbidden) {
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
        realm.c_str(),
        "0",
        opaque_opt,
        MHD_YES,
        qop,
        algo,
        allow_userhash,
        MHD_YES,
        MHD_response_from_buffer_static(
          MHD_HTTP_STATUS_UNAUTHORIZED,
          4, "auth"));
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
