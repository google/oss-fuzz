// Copyright 2019 Google LLC
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
#include <stdlib.h>

#include "blosc/blosc.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < BLOSC_MIN_HEADER_LENGTH) return 0;

  size_t nbytes, cbytes, blocksize;
  blosc_cbuffer_sizes(data, &nbytes, &cbytes, &blocksize);
  if (cbytes != size) return 0;
  if (nbytes == 0) return 0;

  void *output = malloc(nbytes);
  blosc_decompress_ctx(data, output, nbytes, /*numinternalthreads=*/1);
  free(output);
  return 0;
}
