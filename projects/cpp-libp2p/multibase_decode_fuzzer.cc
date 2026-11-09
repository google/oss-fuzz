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
#include <string>

#include <libp2p/multi/multibase_codec/multibase_codec_impl.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == nullptr || size == 0) {
    return 0;
  }
  std::string s(reinterpret_cast<const char *>(data), size);

  libp2p::multi::MultibaseCodecImpl codec;
  // Try decode as-is
  (void)codec.decode(s);

  // Also try with a valid prefix if missing, to reach deeper code paths.
  if (s.size() >= 1 && s[0] != 'f' && s[0] != 'F' && s[0] != 'b' &&
      s[0] != 'B' && s[0] != 'z' && s[0] != 'm') {
    s.insert(s.begin(), 'z');
    (void)codec.decode(s);
  }
  return 0;
}

