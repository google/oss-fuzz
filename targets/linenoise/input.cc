// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

// We need to get directly at linenoiseEdit to bypass the TTY check
#include <linenoise.h>

#define LINENOISE_MAX_LINE 4096

extern "C" void linenoiseWrapper(char* buf, size_t buflen);

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int p[2];
  close(STDOUT_FILENO);
  int dev_null = open("/dev/null", O_WRONLY);
  close(STDIN_FILENO);
  pipe2(p, O_NONBLOCK);
  linenoiseSetMultiLine(1);
  linenoiseHistorySetMaxLen(256);
  char buf[LINENOISE_MAX_LINE];
  ssize_t written = 0;
  while (size > 0) {
    do {
      written = write(p[1], data, 1);
      if (written > 0) {
        data += written;
        size -= written;
      }
    } while (size > 0 && written >= 0);
    linenoiseWrapper(buf, LINENOISE_MAX_LINE);
  }
  return 0;
}
