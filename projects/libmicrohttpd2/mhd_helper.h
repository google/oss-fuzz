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
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "microhttpd2.h"
#include <fuzzer/FuzzedDataProvider.h>

// Forward declaration
extern std::unique_ptr<FuzzedDataProvider> g_fdp;
extern std::mutex g_fdp_mu;

// Daemon options
struct DaemonOpts {
  bool omit_host = false;
  bool bad_cl = false;
  bool keep_alive = false;
  bool extra_headers = false;
  bool use_digest = false;
  bool send_malformed_digest = false;
  bool te_chunked = false;
  bool as_multipart = false;
  std::string realm_hint = "hint";
  std::string boundary = "----fuzz----";
};

// Daemon request handling options
struct DaemonReqOpts {
  std::string realm;
  std::string allowed_user;
  std::string allowed_pass;
  bool force_challenge = false;
  bool force_bad = false;
  bool flip_ok_to_forbidden = false;
  enum MHD_Bool prefer_utf8 = MHD_NO;

  bool use_digest = false;
  MHD_DigestAuthMultiQOP  qop  = MHD_DIGEST_AUTH_MULT_QOP_AUTH;
  MHD_DigestAuthMultiAlgo algo = MHD_DIGEST_AUTH_MULT_ALGO_ANY;

  enum MHD_Bool send_stale = MHD_NO;
  enum MHD_Bool allow_userhash = MHD_NO;
  bool use_opaque = false;

  size_t buf_sz = 4096;
  size_t max_nonstream = 16384;
  enum MHD_HTTP_PostEncoding enc = MHD_HTTP_POST_ENCODING_FORM_URLENCODED;
  bool do_parse_post = false;
  bool do_process_upload = false;
};

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
MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_NONNULL_(3)
const struct MHD_Action* req_cb_stream(void* cls,
                                       struct MHD_Request* MHD_RESTRICT request,
                                       const struct MHD_String* MHD_RESTRICT path,
                                       enum MHD_HTTP_Method method,
                                       uint_fast64_t upload_size);

MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_NONNULL_(3)
const struct MHD_Action* req_cb_process(void* cls,
                                        struct MHD_Request* MHD_RESTRICT request,
                                        const struct MHD_String* MHD_RESTRICT path,
                                        enum MHD_HTTP_Method method,
                                        uint_fast64_t upload_size);

// Provide base64 encoding for the response/request
std::string b64encode(const std::string &in);

// Helper to transform bool to MHD_Bool
enum MHD_Bool ToMhdBool(bool b);

// Helper to convert random string to safe ascii characters only
std::string safe_ascii(const std::string& in, bool allow_space = true);
