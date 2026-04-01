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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* trash is a global scratch buffer used throughout haproxy (e.g. in
 * make_arg_list).  Normal startup initialises it via init_trash_buffers(),
 * but the fuzzer bypasses the full init sequence, so we allocate it once
 * here to avoid a NULL-pointer dereference.
 */
extern THREAD_LOCAL struct buffer trash;

#define FUZZ_TRASH_SIZE 65536

static int trash_initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!trash_initialized) {
    chunk_init(&trash, malloc(FUZZ_TRASH_SIZE), FUZZ_TRASH_SIZE);
    if (!trash.area)
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
