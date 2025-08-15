#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "microhttpd2.h"

// Forward declaration
class FuzzedDataProvider;
extern std::unique_ptr<FuzzedDataProvider> g_fdp;
extern std::mutex g_fdp_mu;

// Helper for sending request to daemon
void send_http_request_blocking(uint16_t port,
                                const std::string& method,
                                const std::string& path,
                                const std::string& auth_user,
                                const std::string& auth_pass,
                                const std::string& body,
                                bool garble_auth);

// Request handling and processing functions for the daemon
MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_NONNULL_(3)
const struct MHD_Action* req_cb(void* cls,
                                struct MHD_Request* MHD_RESTRICT request,
                                const struct MHD_String* MHD_RESTRICT path,
                                enum MHD_HTTP_Method method,
                                uint_fast64_t upload_size);

// Provide base64 encoding for the response/request
static std::string b64encode(const std::string &in);

// Helper to transform bool to MHD_Bool
static inline enum MHD_Bool ToMhdBool(bool b) {
  return b ? MHD_YES : MHD_NO;
}

// Helper to convert random string to safe ascii characters only
static std::string safe_ascii(const std::string& in, bool allow_space = true) {
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
