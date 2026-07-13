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

#include <cstddef>
#include <cstdint>
#include <span>

#include <libp2p/common/types.hpp>
#include <libp2p/protocol_muxer/multiselect/parser.hpp>

using libp2p::BytesIn;
using libp2p::protocol_muxer::multiselect::detail::Parser;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Parser parser;

  // Feed input in small chunks to exercise underflow/overflow paths
  size_t pos = 0;
  while (pos < size) {
    size_t step = 1;
    if (pos < size) {
      step = 1 + (data[pos] & 0x0F);  // 1..16
    }
    if (pos + step > size) {
      step = size - pos;
    }
    BytesIn chunk(data + pos, step);
    auto state = parser.consume(chunk);
    (void)state;
    pos += step;
  }

  // Finalize by resetting and consuming the whole buffer at once
  parser.reset();
  BytesIn all(data, size);
  (void)parser.consume(all);

  return 0;
}

