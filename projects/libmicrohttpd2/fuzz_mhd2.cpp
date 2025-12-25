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
#include <vector>
#include <algorithm>
#include <cstdarg>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "microhttpd2.h"
#include "fuzzer/FuzzedDataProvider.h"

static inline enum MHD_Bool ToMhdBool(bool b) {
  return b ? MHD_YES : MHD_NO;
}

static void dummy_log(void*, enum MHD_StatusCode, const char*, va_list) {
  // Do nothing
}

static MHD_FN_PAR_NONNULL_(2) MHD_FN_PAR_NONNULL_(3)
const struct MHD_Action* req_cb(void* cls,
                                struct MHD_Request* request,
                                const struct MHD_String* path,
                                enum MHD_HTTP_Method method,
                                uint_fast64_t upload_size) {

  const std::string* body = static_cast<const std::string*>(cls);
  struct MHD_Response* r = MHD_response_from_buffer(
      MHD_HTTP_STATUS_OK, body->size(), body->c_str(),
      nullptr, nullptr);
  if (!r) {
    return nullptr;
  }
  return MHD_action_from_response(request, r);
}

void fuzz_digest_auth_calc(FuzzedDataProvider& fdp) {
  std::string realm  = fdp.ConsumeRandomLengthString(40);
  std::string user   = fdp.ConsumeRandomLengthString(24);
  std::string pass   = fdp.ConsumeRandomLengthString(24);

  enum MHD_DigestAuthAlgo alg =
      fdp.PickValueInArray<enum MHD_DigestAuthAlgo>({
        MHD_DIGEST_AUTH_ALGO_MD5,
        MHD_DIGEST_AUTH_ALGO_SHA256,
        MHD_DIGEST_AUTH_ALGO_SHA512_256
      });
  size_t hsz = MHD_digest_get_hash_size(alg);
  if (hsz > 0 && hsz <= 128) {
    std::vector<uint8_t> bin(hsz);
    std::vector<uint8_t> ud(hsz);
    std::vector<char>    hex(hsz * 2 + 1);
    (void) MHD_digest_auth_calc_userhash(alg, user.c_str(), realm.c_str(), bin.size(), bin.data());
    (void) MHD_digest_auth_calc_userhash_hex(alg, user.c_str(), realm.c_str(), hex.size(), hex.data());
    (void) MHD_digest_auth_calc_userdigest(alg, user.c_str(), realm.c_str(), pass.c_str(), ud.size(), ud.data());
  }
}

struct MHD_Response* fuzz_response_creation(FuzzedDataProvider& fdp) {
  // Create random body string for response
  const size_t body_len = fdp.ConsumeIntegralInRange<size_t>(0, std::min<size_t>(fdp.remaining_bytes(), 2048));
  std::string body = fdp.ConsumeBytesAsString(body_len);

  struct MHD_Response* r = nullptr;
  enum MHD_HTTP_StatusCode sc =
      fdp.PickValueInArray<enum MHD_HTTP_StatusCode>({
        MHD_HTTP_STATUS_OK, MHD_HTTP_STATUS_CREATED, MHD_HTTP_STATUS_NO_CONTENT,
        MHD_HTTP_STATUS_PARTIAL_CONTENT, MHD_HTTP_STATUS_BAD_REQUEST,
        MHD_HTTP_STATUS_UNAUTHORIZED, MHD_HTTP_STATUS_FORBIDDEN,
        MHD_HTTP_STATUS_NOT_FOUND, MHD_HTTP_STATUS_INTERNAL_SERVER_ERROR
      });

  if (fdp.ConsumeBool()) {
    r = MHD_response_from_buffer(sc, body.size(), body.data(), nullptr, nullptr);
  } else if (fdp.ConsumeBool()) {
    r = MHD_response_from_buffer_static(sc, body.size(), body.c_str());
  } else {
    r = MHD_response_from_empty(sc);
  }

  return r;
}

void fuzz_response_config(FuzzedDataProvider& fdp, struct MHD_Response* r) {
  std::string header1 = fdp.ConsumeRandomLengthString(24); if (header1.empty()) header1 = "H1";
  std::string header2 = fdp.ConsumeRandomLengthString(24); if (header2.empty()) header2 = "H2";
  std::string header3 = fdp.ConsumeRandomLengthString(24); if (header3.empty()) header3 = "H3";
  std::string val1 = fdp.ConsumeRandomLengthString(64); if (val1.empty()) val1 = "V1";
  std::string val2 = fdp.ConsumeRandomLengthString(64); if (val2.empty()) val2 = "V2";
  std::string val3 = fdp.ConsumeRandomLengthString(64); if (val3.empty()) val3 = "V3";

  // Set random headers
  MHD_response_add_header(r, "Content-Type", fdp.ConsumeBool() ? "text/plain" : "application/octet-stream");
  MHD_response_add_header(r, header1.c_str(), val1.c_str());
  MHD_response_add_header(r, header2.c_str(), val2.c_str());
  MHD_response_add_header(r, header3.c_str(), val3.c_str());

  // Set predefined headers
  MHD_response_add_predef_header(
    r, fdp.PickValueInArray<enum MHD_PredefinedHeader>({MHD_PREDEF_ACCEPT_CHARSET, MHD_PREDEF_ACCEPT_LANGUAGE}),
    fdp.ConsumeRandomLengthString(32).c_str()
  );

  // Set boolean configurations
  { auto opt = MHD_R_OPTION_REUSABLE( ToMhdBool(fdp.ConsumeBool())); (void) MHD_response_set_option(r, &opt); }
  { auto opt = MHD_R_OPTION_HEAD_ONLY_RESPONSE( ToMhdBool(fdp.ConsumeBool())); (void) MHD_response_set_option(r, &opt); }
  { auto opt = MHD_R_OPTION_CHUNKED_ENC( ToMhdBool(fdp.ConsumeBool())); (void) MHD_response_set_option(r, &opt); }
  { auto opt = MHD_R_OPTION_CONN_CLOSE( ToMhdBool(fdp.ConsumeBool())); (void) MHD_response_set_option(r, &opt); }

  // Create random data for response generation
  char tmpl[] = "/tmp/mhd2_fuzz_XXXXXX";
  int fd = mkstemp(tmpl);
  if (fd >= 0) {
    std::string bytes = fdp.ConsumeRandomLengthString(512);
    if (!bytes.empty()) {
      write(fd, bytes.data(), bytes.size());
    }

    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz > 0) {
      uint_fast64_t off = fdp.ConsumeIntegralInRange<uint_fast64_t>(0, (uint_fast64_t)sz);
      uint_fast64_t len = fdp.ConsumeIntegralInRange<uint_fast64_t>(0, (uint_fast64_t)(sz - off));
      struct MHD_Response* rf = MHD_response_from_fd(
          fdp.PickValueInArray<enum MHD_HTTP_StatusCode>({
            MHD_HTTP_STATUS_OK, MHD_HTTP_STATUS_PARTIAL_CONTENT, MHD_HTTP_STATUS_NO_CONTENT
          }),
          fd, off, len);
      if (rf) MHD_response_destroy(rf); else close(fd);
    } else {
      close(fd);
    }
    unlink(tmpl);
  }

  // Pipe random response
  int pfd[2];
  if (0 == pipe(pfd)) {
    std::string pbytes = fdp.ConsumeRandomLengthString(256);
    if (!pbytes.empty()) (void)!write(pfd[1], pbytes.data(), pbytes.size());
    close(pfd[1]);
    struct MHD_Response* rp = MHD_response_from_pipe(
        fdp.PickValueInArray<enum MHD_HTTP_StatusCode>({
          MHD_HTTP_STATUS_OK, MHD_HTTP_STATUS_NO_CONTENT
        }),
        pfd[0]);
    if (rp) {
      MHD_response_destroy(rp);
    } else {
      close(pfd[0]);
    }
  }
}

void daemon_configuration(FuzzedDataProvider& fdp, MHD_Daemon* d) {
  using PollEnum = decltype(MHD_SPS_AUTO);
  static constexpr PollEnum kPollChoices[] = {
      MHD_SPS_AUTO, MHD_SPS_SELECT, MHD_SPS_POLL, MHD_SPS_EPOLL,
  };
  PollEnum ps = fdp.PickValueInArray(kPollChoices);
  auto opt1 = MHD_D_OPTION_POLL_SYSCALL(ps);
  MHD_daemon_set_option(d, &opt1);

  using AddrEnum = decltype(MHD_AF_NONE);
  static constexpr AddrEnum kAddrChoices[] = {
      MHD_AF_NONE, MHD_AF_AUTO, MHD_AF_INET4, MHD_AF_INET6,
  };
  uint_least16_t port = fdp.ConsumeIntegralInRange<uint_least16_t>(0, 65535);
  AddrEnum af = fdp.PickValueInArray(kAddrChoices);
  auto opt2 = MHD_D_OPTION_BIND_PORT(af, port);
  (void) MHD_daemon_set_option(d, &opt2);

  auto opt3 = MHD_D_OPTION_DEFAULT_TIMEOUT_MILSEC(fdp.ConsumeIntegralInRange<unsigned>(0, 10000));
  MHD_daemon_set_option(d, &opt3);

  auto opt4 = MHD_D_OPTION_CONN_MEMORY_LIMIT(fdp.ConsumeIntegralInRange<size_t>(0, 1<<16));
  MHD_daemon_set_option(d, &opt4);

  auto opt5 = MHD_D_OPTION_LOG_CALLBACK(&dummy_log, nullptr);
  MHD_daemon_set_option(d, &opt5);

  std::vector<uint8_t> ent = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 32));
  auto opt6 = MHD_D_OPTION_RANDOM_ENTROPY(ent.size(),
      const_cast<void*>(static_cast<const void*>(ent.data()))
  );
  MHD_daemon_set_option(d, &opt6);

  auto opt7 = MHD_D_OPTION_REREGISTER_ALL(ToMhdBool(fdp.ConsumeBool()));
  MHD_daemon_set_option(d, &opt7);
}

void fuzz_daemon_lifecycle(FuzzedDataProvider& fdp) {
  // Create random body string for response
  const size_t body_len = fdp.ConsumeIntegralInRange<size_t>(0, std::min<size_t>(fdp.remaining_bytes(), 2048));
  std::string body = fdp.ConsumeBytesAsString(body_len);

  struct MHD_Daemon* d = MHD_daemon_create(&req_cb, &body);
  if (!d) {
    return;
  }

  // Fuzz with random fixed queries
  union MHD_DaemonInfoFixedData dfix{};
  const int n = fdp.ConsumeIntegralInRange<int>(1, 6);
  using FixedEnum = decltype(MHD_DAEMON_INFO_FIXED_POLL_SYSCALL);
  static constexpr FixedEnum kFixedChoices[] = {
      MHD_DAEMON_INFO_FIXED_POLL_SYSCALL,
      MHD_DAEMON_INFO_FIXED_AGGREAGATE_FD,
      MHD_DAEMON_INFO_FIXED_NUM_WORK_THREADS,
      MHD_DAEMON_INFO_FIXED_BIND_PORT,
      MHD_DAEMON_INFO_FIXED_LISTEN_SOCKET,
      MHD_DAEMON_INFO_FIXED_TLS_BACKEND,
      MHD_DAEMON_INFO_FIXED_DEFAULT_TIMEOUT_MILSEC,
      MHD_DAEMON_INFO_FIXED_GLOBAL_CONNECTION_LIMIT,
      MHD_DAEMON_INFO_FIXED_PER_IP_LIMIT,
      MHD_DAEMON_INFO_FIXED_SUPPRESS_DATE_HEADER,
      MHD_DAEMON_INFO_FIXED_CONN_MEMORY_LIMIT,
      MHD_DAEMON_INFO_FIXED_FD_NUMBER_LIMIT,
  };
  for (int i = 0; i < n; ++i) {
    daemon_configuration(fdp, d);
    FixedEnum which = fdp.PickValueInArray(kFixedChoices);
    MHD_daemon_get_info_fixed(d, which, &dfix);
  }

  // Fuzz with random dynamic queries
  union MHD_DaemonInfoDynamicData ddyn{};
  const int m = fdp.ConsumeIntegralInRange<int>(1, 6);
  using DynEnum = decltype(MHD_DAEMON_INFO_DYNAMIC_MAX_TIME_TO_WAIT);
  static constexpr DynEnum kDynChoices[] = {
      MHD_DAEMON_INFO_DYNAMIC_MAX_TIME_TO_WAIT,
      MHD_DAEMON_INFO_DYNAMIC_HAS_CONNECTIONS,
  };
  for (int i = 0; i < m; ++i) {
    daemon_configuration(fdp, d);
    DynEnum which = fdp.PickValueInArray(kDynChoices);
    MHD_daemon_get_info_dynamic(d, which, &ddyn);
  }

  MHD_daemon_destroy(d);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size <= 0) {
    return 0;
  }
  FuzzedDataProvider fdp(data, size);

  // Fuzz digest_auth_calc targets
  fuzz_digest_auth_calc(fdp);

  // Create responses with random choices
  struct MHD_Response* r = fuzz_response_creation(fdp);

  // Fuzz response configurations
  if (r) {
    fuzz_response_config(fdp, r);
    MHD_response_destroy(r);
  }

  // Fuzz daemon lifecycle
  fuzz_daemon_lifecycle(fdp);

  return 0;
}
