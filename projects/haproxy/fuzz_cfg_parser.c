/*
# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <haproxy/cfgparse.h>
#include <haproxy/chunk.h>
#include <haproxy/global.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FUZZ_TRASH_SIZE 65536

static int trash_initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* One-time init: use init_trash_buffers() to properly initialize all trash
   * buffers (trash, trash_buf1, trash_buf2 and their large/small variants).
   * This mirrors haproxy's alloc_early_trash + alloc_trash_buffers_per_thread
   * startup sequence. */
  if (!trash_initialized) {
    global.tune.bufsize = FUZZ_TRASH_SIZE;
    global.tune.bufsize_large = FUZZ_TRASH_SIZE * 2;
    global.tune.bufsize_small = 1024;
    if (!init_trash_buffers(1))
      return 0;
    if (!init_trash_buffers(0))
      return 0;
    trash_initialized = 1;
  }

  struct cfgfile dummy_cfg = {
      .filename = "fuzzer",
      .content = (const char *)data,
      .size = size,
  };
  if (size < 50)
    return 0;

  parse_cfg(&dummy_cfg);
  return 0;
}
