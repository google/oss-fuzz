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

#include <libp2p/multi/multiaddress.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == nullptr || size == 0) {
    return 0;
  }
  std::string s(reinterpret_cast<const char *>(data), size);

  // Multiaddress strings typically start with '/'. Ensure both paths are tested.
  auto try_parse = [](std::string_view str) {
    auto res = libp2p::multi::Multiaddress::create(str);
    if (res) {
      const auto &ma = res.value();
      (void)ma.getStringAddress();
      (void)ma.getBytesAddress();
      (void)ma.getPeerId();
      (void)ma.getProtocols();
      (void)ma.getProtocolsWithValues();
      (void)ma.splitFirst();
    }
  };

  try_parse(s);
  if (!s.empty() && s.front() != '/') {
    s.insert(s.begin(), '/');
    try_parse(s);
  }
  return 0;
}

