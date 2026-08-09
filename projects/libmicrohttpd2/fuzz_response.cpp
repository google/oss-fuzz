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
#include <unistd.h>
#include <sys/types.h>

#include <vector>
#include <algorithm>

#include "mhd_helper.h"

static void request_ended_cb(void *cls,
                             const struct MHD_RequestEndedData *data,
                             void *request_app_context) {
  // Do nothing
}

static enum MHD_HTTP_StatusCode pick_status_code(FuzzedDataProvider &fdp) {
  // Randomly pick a valid or invalid HTTP response status code
  return fdp.ConsumeBool()
      ? fdp.PickValueInArray({
          MHD_HTTP_STATUS_OK, MHD_HTTP_STATUS_CREATED, MHD_HTTP_STATUS_NO_CONTENT,
          MHD_HTTP_STATUS_PARTIAL_CONTENT, MHD_HTTP_STATUS_BAD_REQUEST,
          MHD_HTTP_STATUS_UNAUTHORIZED, MHD_HTTP_STATUS_FORBIDDEN,
          MHD_HTTP_STATUS_NOT_FOUND, MHD_HTTP_STATUS_INTERNAL_SERVER_ERROR })
      : (enum MHD_HTTP_StatusCode)(fdp.ConsumeIntegralInRange<int>(0, 999));
}

static MHD_Response* create_response(FuzzedDataProvider &fdp,
                                     enum MHD_HTTP_StatusCode sc) {
  struct MHD_Response* r = nullptr;

  // Generate random response body
  const size_t body_len = fdp.ConsumeIntegralInRange<size_t>(
      0, std::min<size_t>(fdp.remaining_bytes(), 8192));
  std::string body = fdp.ConsumeBytesAsString(body_len);


  // Randomly select which constructing function to use for respone object creation
  enum CtorKind {
    EMPTY, BUF_STATIC, BUF_COPY, IOVEC, FROM_FD, FROM_PIPE
  };
  CtorKind ctor = fdp.PickValueInArray<CtorKind>(
      {EMPTY, BUF_STATIC, BUF_COPY, IOVEC, FROM_FD, FROM_PIPE});

  switch (ctor) {
    default:
    case EMPTY: {
      // Create empty response
      r = MHD_response_from_empty(sc);
      break;
    }
    case BUF_STATIC: {
      // Create response with random body and static buffer status
      r = MHD_response_from_buffer_static(sc, body.size(), body.c_str());
      break;
    }
    case BUF_COPY: {
      // Create response with random body and copy buffer in
      r = MHD_response_from_buffer_copy(sc, body.size(), body.data());
      break;
    }
    case IOVEC: {
      // Create response from random IO vector
      unsigned cnt = fdp.ConsumeIntegralInRange<unsigned>(0, 6);
      std::vector<MHD_IoVec> iov(cnt);
      std::vector<std::string> chunks; chunks.reserve(cnt);
      for (unsigned i=0;i<cnt;i++) {
        chunks.push_back(fdp.ConsumeBytesAsString(
                           fdp.ConsumeIntegralInRange<size_t>(0, 1024)));
        iov[i].iov_base = chunks.back().data();
        iov[i].iov_len  = chunks.back().size();
      }
      r = MHD_response_from_iovec(sc, cnt ? cnt : 0, cnt ? iov.data() : nullptr, nullptr, nullptr);
      break;
    }
    case FROM_FD: {
      // Create response from file with random data
      char path[] = "/tmp/mhdrespXXXXXX";
      int fd = mkstemp(path);
      if (fd >= 0) {
        unlink(path);
        if (!body.empty()) (void) ::write(fd, body.data(), body.size());
        uint64_t sz = (uint64_t)body.size();
        uint64_t off = 0;
        if (fdp.ConsumeBool()) {
          off = std::min<uint64_t>(sz, fdp.ConsumeIntegral<uint64_t>() % (sz + 1));
        }
        uint64_t len = (sz > off) ? (fdp.ConsumeIntegral<uint64_t>() % (sz - off + 1)) : 0;
        r = MHD_response_from_fd(sc, fd, off, len);
        if (!r) {
          close(fd);
        }
      }
      break;
    }
    case FROM_PIPE: {
      // Create response by piping in random data
      int pfd[2];
      if (0 == pipe(pfd)) {
        std::string pbytes = fdp.ConsumeBytesAsString(
                               fdp.ConsumeIntegralInRange<size_t>(0, 2048));
        if (!pbytes.empty()) {
          ::write(pfd[1], pbytes.data(), pbytes.size());
        }
        close(pfd[1]);
        r = MHD_response_from_pipe(sc, pfd[0]);
        if (!r) {
          close(pfd[0]);
        }
      }
      break;
    }
  }

  return r;
}

static void add_headers(FuzzedDataProvider &fdp, MHD_Response *r) {
  const char* ct = fdp.ConsumeBool() ? "text/plain" : "application/octet-stream";
  MHD_response_add_header(r, "Content-Type", ct);

  // Add random standard headers
  size_t num_headers = fdp.ConsumeIntegralInRange<size_t>(0, 10);
  for (size_t i = 0; i < num_headers; i++) {
    std::string name = safe_ascii(fdp.ConsumeRandomLengthString(20), false);
    std::string val  = safe_ascii(fdp.ConsumeRandomLengthString(60), true);
    MHD_response_add_header(r, name.c_str(), val.c_str());
  }

  // Add random predefined header
  enum MHD_PredefinedHeader which =
    fdp.PickValueInArray<enum MHD_PredefinedHeader>(
      { MHD_PREDEF_ACCEPT_CHARSET, MHD_PREDEF_ACCEPT_LANGUAGE });
  std::string value = safe_ascii(fdp.ConsumeRandomLengthString(32));
  MHD_response_add_predef_header(r, which, value.c_str());
}

static void randomise_response_options(FuzzedDataProvider &fdp, MHD_Response *r) {
  if (fdp.ConsumeBool()) {
    auto o = MHD_R_OPTION_REUSABLE(ToMhdBool(fdp.ConsumeBool()));
    MHD_response_set_option(r, &o);
  }
  if (fdp.ConsumeBool()) {
    auto o = MHD_R_OPTION_HEAD_ONLY_RESPONSE(ToMhdBool(fdp.ConsumeBool()));
    MHD_response_set_option(r, &o);
  }
  if (fdp.ConsumeBool()) {
    auto o = MHD_R_OPTION_CHUNKED_ENC(ToMhdBool(fdp.ConsumeBool()));
    MHD_response_set_option(r, &o);
  }
  if (fdp.ConsumeBool()) {
    auto o = MHD_R_OPTION_CONN_CLOSE(ToMhdBool(fdp.ConsumeBool()));
    MHD_response_set_option(r, &o);
  }
  if (fdp.ConsumeBool()) {
    auto o = MHD_R_OPTION_HTTP_1_0_SERVER(ToMhdBool(fdp.ConsumeBool()));
    MHD_response_set_option(r, &o);
  }
  if (fdp.ConsumeBool()) {
    auto o = MHD_R_OPTION_HTTP_1_0_COMPATIBLE_STRICT(ToMhdBool(fdp.ConsumeBool()));
    MHD_response_set_option(r, &o);
  }
  if (fdp.ConsumeBool()) {
    auto o = MHD_R_OPTION_INSANITY_HEADER_CONTENT_LENGTH(ToMhdBool(fdp.ConsumeBool()));
    MHD_response_set_option(r, &o);
  }
  if (fdp.ConsumeBool()) {
    auto o = MHD_R_OPTION_TERMINATION_CALLBACK(&request_ended_cb, nullptr);
    MHD_response_set_option(r, &o);
  }
}

static void add_auth(FuzzedDataProvider &fdp, MHD_Response *r,
                     enum MHD_HTTP_StatusCode sc) {
  if (sc == MHD_HTTP_STATUS_UNAUTHORIZED) {
    // Randomly add different challenge under 401 status code
    if (fdp.ConsumeBool()) {
      // Use digest challenge
      std::string realm = safe_ascii(fdp.ConsumeRandomLengthString(24));
      MHD_response_add_auth_basic_challenge(r, realm.c_str(), ToMhdBool(fdp.ConsumeBool()));
      if (fdp.ConsumeBool()) {
        std::string drealm = safe_ascii(fdp.ConsumeRandomLengthString(24));
        const char* opaque = fdp.ConsumeBool() ? "opaque" : nullptr;
        const char* domain = fdp.ConsumeBool() ? "/a /b"  : nullptr;
        enum MHD_DigestAuthMultiQOP mqop =
          fdp.ConsumeBool()? MHD_DIGEST_AUTH_MULT_QOP_AUTH : MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT;
        enum MHD_DigestAuthMultiAlgo malgo =
          fdp.ConsumeBool()? MHD_DIGEST_AUTH_MULT_ALGO_ANY : MHD_DIGEST_AUTH_MULT_ALGO_MD5;
        MHD_response_add_auth_digest_challenge(
            r, drealm.c_str(), opaque, domain, ToMhdBool(fdp.ConsumeBool()),
            mqop, malgo, ToMhdBool(fdp.ConsumeBool()), ToMhdBool(fdp.ConsumeBool()));
      }
    } else {
      // Use basic challenge
      std::string realm = safe_ascii(fdp.ConsumeRandomLengthString(24));
      const char* opaque = fdp.ConsumeBool() ? "opaque" : nullptr;
      const char* domain = fdp.ConsumeBool() ? "/a /b"  : nullptr;
      enum MHD_DigestAuthMultiQOP mqop =
        fdp.ConsumeBool()? MHD_DIGEST_AUTH_MULT_QOP_AUTH : MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT;
      enum MHD_DigestAuthMultiAlgo malgo =
        fdp.ConsumeBool()? MHD_DIGEST_AUTH_MULT_ALGO_ANY : MHD_DIGEST_AUTH_MULT_ALGO_MD5;
      MHD_response_add_auth_digest_challenge(
          r, realm.c_str(), opaque, domain, ToMhdBool(fdp.ConsumeBool()),
          mqop, malgo, ToMhdBool(fdp.ConsumeBool()),
          ToMhdBool(fdp.ConsumeBool()));
      if (fdp.ConsumeBool()) {
        std::string brealm = safe_ascii(fdp.ConsumeRandomLengthString(24));
        MHD_response_add_auth_basic_challenge(r, brealm.c_str(), ToMhdBool(fdp.ConsumeBool()));
      }
    }
  } else {
    // For all other status code, randomly determine if challenges are added

    // Randomly choose if basic challenge is used or not
    if (fdp.ConsumeBool()) {
      std::string realm = safe_ascii(fdp.ConsumeRandomLengthString(24));
      MHD_response_add_auth_basic_challenge(r, realm.c_str(), ToMhdBool(fdp.ConsumeBool()));
    }

    // Randomly choose if disgest challenge is used or not
    if (fdp.ConsumeBool()) {
      std::string realm = safe_ascii(fdp.ConsumeRandomLengthString(24));
      const char* opaque = fdp.ConsumeBool() ? "opaque" : nullptr;
      const char* domain = fdp.ConsumeBool() ? "/a /b"  : nullptr;
      enum MHD_DigestAuthMultiQOP mqop =
        fdp.ConsumeBool()? MHD_DIGEST_AUTH_MULT_QOP_AUTH : MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT;
      enum MHD_DigestAuthMultiAlgo malgo =
        fdp.ConsumeBool()? MHD_DIGEST_AUTH_MULT_ALGO_ANY : MHD_DIGEST_AUTH_MULT_ALGO_MD5;
      MHD_response_add_auth_digest_challenge(
          r, realm.c_str(), opaque, domain, ToMhdBool(fdp.ConsumeBool()),
          mqop, malgo, ToMhdBool(fdp.ConsumeBool()), ToMhdBool(fdp.ConsumeBool()));
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }
  FuzzedDataProvider fdp(data, size);

  // Pick a random response status code
  enum MHD_HTTP_StatusCode sc = pick_status_code(fdp);

  // Create a random response object
  struct MHD_Response* r = create_response(fdp, sc);
  if (!r) {
    return 0;
  }

  // Add random headers into the response object
  add_headers(fdp, r);

  // Set random options for the response object
  randomise_response_options(fdp, r);

  // Add authentication challenges to response
  add_auth(fdp, r, sc);

  // Fuzz additional targets on response status
  MHD_HTTP_status_code_to_string(sc);
  MHD_status_code_to_string((enum MHD_StatusCode)sc);

  // Destory the response object
  MHD_response_destroy(r);
  return 0;
}
