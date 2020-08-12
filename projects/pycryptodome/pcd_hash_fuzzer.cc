// Copyright 2020 Google LLC
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

#include "common.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#ifndef HASHTYPE
#error Macro HASHTYPE must be defined.
#endif

#define CONCAT_TYPE(x) _PASTE2(HASHTYPE, x)

#define init CONCAT_TYPE(_init)
#define update CONCAT_TYPE(_update)
#define digest CONCAT_TYPE(_digest)
#define destroy CONCAT_TYPE(_destroy)

#define str(x) #x
#define xstr(x) str(x)
// #define HASHTYPE_STR xstr(HASHTYPE)

static std::string to_include = xstr(HASHTYPE);
to_include.append(".c");

#include to_include

#ifndef DIGEST_SIZE
#define DIGEST_SIZE CONCAT_TYPE(_DIGEST_SIZE)
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (!size)
    return 0;

  FuzzedDataProvider stream(data, size);
  hash_state *hs;
  if (init(&hs))
    return 0;

  while (stream.remaining_bytes()) {
    size_t num_bytes = stream.ConsumeIntegral<size_t>();
    std::vector<uint8_t> buffer = stream.ConsumeBytes<uint8_t>(num_bytes);

    if (update(hs, buffer.data(), buffer.size()))
      goto error;
  }

  uint8_t result[DIGEST_SIZE];
  digest(hs, result);

error:
  destroy(hs);
  return 0;
}
