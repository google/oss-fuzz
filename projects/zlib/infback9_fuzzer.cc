// Copyright 2026 Google LLC
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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" {
#include "zlib.h"
#include "contrib/infback9/infback9.h"
}

struct Input {
  const uint8_t *data;
  size_t size;
  bool used;
};

struct Output {
  size_t size;
};

static unsigned InputCallback(void *desc, unsigned char **buf) {
  Input *input = static_cast<Input *>(desc);
  if (input->used || input->size == 0) {
    *buf = nullptr;
    return 0;
  }

  input->used = true;
  *buf = const_cast<unsigned char *>(input->data);
  return static_cast<unsigned>(input->size);
}

static int OutputCallback(void *desc, unsigned char *, unsigned size) {
  Output *output = static_cast<Output *>(desc);
  output->size += size;
  if (output->size > (1U << 20)) {
    return 1;
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 1U << 20) {
    return 0;
  }

  z_stream strm;
  unsigned char window[1U << 16];
  Input input = {data, size, false};
  Output output = {0};

  memset(&strm, 0, sizeof(strm));
  if (inflateBack9Init(&strm, window) != Z_OK) {
    return 0;
  }

  strm.next_in = Z_NULL;
  strm.avail_in = 0;
  (void)inflateBack9(&strm, InputCallback, &input, OutputCallback, &output);
  (void)inflateBack9End(&strm);
  return 0;
}
