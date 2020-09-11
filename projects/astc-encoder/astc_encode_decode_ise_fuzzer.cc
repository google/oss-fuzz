// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "astcenc_internal.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

static constexpr size_t kMaxOutBufSize = 64;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  FuzzedDataProvider stream(data, size);
  int quantization_level = stream.ConsumeIntegral<int>();

  // encode_ise and decode_ise will each write a max of 64 bytes to the buffer
  std::vector<uint8_t> buffer = stream.ConsumeBytes<uint8_t>(kMaxOutBufSize);
  uint8_t out[kMaxOutBufSize];

  encode_ise(quantization_level, buffer.size(), buffer.data(), out, 0);
  decode_ise(quantization_level, buffer.size(), buffer.data(), out, 0);

  return 0;
}
