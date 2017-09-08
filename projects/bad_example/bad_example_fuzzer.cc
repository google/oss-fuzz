// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <signal.h>
#include <unistd.h>

#include "zlib.h"

static Bytef buffer[256 * 1024] = { 0 };


#ifdef INTENTIONAL_STARTUP_CRASH
void bad_term_handler(int signum) {
  _exit(0);
}
#endif

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
#ifdef INTENTIONAL_STARTUP_CRASH
  // Simulates the worst case, fuzz target silently dies without any error.
  struct sigaction action = { 0 };
  action.sa_handler = bad_term_handler;
  sigaction(SIGTERM, &action, NULL);

  // Cannot call _exit(0) directly, as it's even worse -- sancov does not print
  // any coverage information in that case.
  kill(getpid(), SIGTERM);
#endif

  uLongf buffer_length = static_cast<uLongf>(sizeof(buffer));
  if (Z_OK != uncompress(buffer, &buffer_length, data,
                         static_cast<uLong>(size))) {
    return 0;
  }
  return 0;
}
