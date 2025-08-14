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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <mutex>
#include <memory>
#include <cstdint>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mhd_helper.h"
#include <fuzzer/FuzzedDataProvider.h>

static constexpr uint16_t kPort = 54321;
static uint16_t g_listen_port = kPort;

static struct MHD_Daemon* g_daemon = nullptr;
static std::once_flag g_start_once;

std::unique_ptr<FuzzedDataProvider> g_fdp;
std::mutex g_fdp_mu;

static void start_daemon_once() {
  if (g_daemon) return;

  // Tiny deterministic entropy (fine for fuzzing)
  unsigned char entropy[32];
  for (size_t i = 0; i < sizeof(entropy); ++i)
    entropy[i] = (unsigned char)(0xA5 ^ (i * 17));

  bool started = false;
  for (int i = 0; i < 8 && !started; ++i) {
    const uint16_t try_port = static_cast<uint16_t>(kPort + i);

    g_daemon = MHD_daemon_create(&req_cb, NULL);
    if (!g_daemon) continue;

    // Only pass options you are 100% sure exist in YOUR header.
    // Start with the absolute minimum: bind + (optional) entropy.
    auto sc = MHD_DAEMON_SET_OPTIONS(
                g_daemon,
                MHD_D_OPTION_BIND_PORT(MHD_AF_INET4, try_port),
                MHD_D_OPTION_RANDOM_ENTROPY(sizeof(entropy), entropy)
              );
    if (sc != MHD_SC_OK) {
      MHD_daemon_destroy(g_daemon);
      g_daemon = nullptr;
      continue;
    }

    // NOTE: do NOT set WM_WORKER_THREADS here yet.
    if (MHD_daemon_start(g_daemon) != MHD_SC_OK) {
      MHD_daemon_destroy(g_daemon);
      g_daemon = nullptr;
      continue;
    }

    g_listen_port = try_port;
    started = true;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::call_once(g_start_once, start_daemon_once);
  if (!g_daemon) {
    return 0;
  }

  size_t reqs = 0;

  // Put FuzzedDataProvider to global
  {
    std::lock_guard<std::mutex> lk(g_fdp_mu);
    g_fdp = std::make_unique<FuzzedDataProvider>(data, size);
  }

  {
    std::lock_guard<std::mutex> lk(g_fdp_mu);
    if (g_fdp) {
      reqs = 1 + g_fdp->ConsumeIntegralInRange<size_t>(0, 7);
    }
  }

  for (size_t i = 0; i < reqs; ++i) {
    std::string method = "GET", path, user, pass, body;
    bool garble_auth = false;

    // Prepare HTTP request in locked session
    {
      std::lock_guard<std::mutex> lk(g_fdp_mu);
      if (g_fdp) {
        static const char* kCommon[] = {"GET","POST","PUT","DELETE","HEAD","PATCH","OPTIONS"};
        if (g_fdp->ConsumeBool())
          method = g_fdp->PickValueInArray(kCommon);
        else {
          method = g_fdp->ConsumeRandomLengthString(8);
          if (method.empty()) method = "GET";
        }

        path = g_fdp->ConsumeRandomLengthString(
                 g_fdp->ConsumeIntegralInRange<size_t>(0, 64));
        for (char &c : path) if (c == ' ') c = '_';

        user = g_fdp->ConsumeRandomLengthString(16);
        pass = g_fdp->ConsumeRandomLengthString(16);
        garble_auth = g_fdp->ConsumeBool();

        if (method == "POST" || g_fdp->ConsumeBool()) {
          body = g_fdp->ConsumeBytesAsString(
                   g_fdp->ConsumeIntegralInRange<size_t>(0, 2048));
        }
      }
    }

    // Send request
    send_http_request_blocking(g_listen_port, method, path, user, pass, body, garble_auth);

    {
      std::lock_guard<std::mutex> lk(g_fdp_mu);
      if (!g_fdp || g_fdp->remaining_bytes() < 8) {
        break;
      }
    }
  }

  // Free FDP
  {
    std::lock_guard<std::mutex> lk(g_fdp_mu);
    g_fdp.reset();
  }

  return 0;
}

extern "C" void LLVMFuzzerTearDown() {
  if (g_daemon) {
    MHD_daemon_destroy(g_daemon);
    g_daemon = nullptr;
  }
}
