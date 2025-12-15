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

#include <cstdint>
#include <string>
#include <vector>
#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_js_format.h"
#include "fuzz_common.h"

static const char* kCiphers[] = {
  "aes-128-cbc","aes-128-cbc-hmac-sha1","aes-128-cbc-hmac-sha256","aes-128-ccm","aes-128-cfb",
  "aes-128-cfb1","aes-128-cfb8","aes-128-ctr","aes-128-ecb","aes-128-gcm","aes-128-ocb","aes-128-ofb",
  "aes-128-xts","aes-192-cbc","aes-192-ccm","aes-192-cfb","aes-192-cfb1","aes-192-cfb8","aes-192-ctr",
  "aes-192-ecb","aes-192-gcm","aes-192-ocb","aes-192-ofb","aes-256-cbc","aes-256-cbc-hmac-sha1",
  "aes-256-cbc-hmac-sha256","aes-256-ccm","aes-256-cfb","aes-256-cfb1","aes-256-cfb8","aes-256-ctr",
  "aes-256-ecb","aes-256-gcm","aes-256-ocb","aes-256-ofb","aes-256-xts","aes128","aes128-wrap","aes192",
  "aes192-wrap","aes256","aes256-wrap","aria-128-cbc","aria-128-ccm","aria-128-cfb","aria-128-cfb1",
  "aria-128-cfb8","aria-128-ctr","aria-128-ecb","aria-128-gcm","aria-128-ofb","aria-192-cbc",
  "aria-192-ccm","aria-192-cfb","aria-192-cfb1","aria-192-cfb8","aria-192-ctr","aria-192-ecb",
  "aria-192-gcm","aria-192-ofb","aria-256-cbc","aria-256-ccm","aria-256-cfb","aria-256-cfb1",
  "aria-256-cfb8","aria-256-ctr","aria-256-ecb","aria-256-gcm","aria-256-ofb","aria128","aria192",
  "aria256","camellia-128-cbc","camellia-128-cfb","camellia-128-cfb1","camellia-128-cfb8",
  "camellia-128-ctr","camellia-128-ecb","camellia-128-ofb","camellia-192-cbc","camellia-192-cfb",
  "camellia-192-cfb1","camellia-192-cfb8","camellia-192-ctr","camellia-192-ecb","camellia-192-ofb",
  "camellia-256-cbc","camellia-256-cfb","camellia-256-cfb1","camellia-256-cfb8","camellia-256-ctr",
  "camellia-256-ecb","camellia-256-ofb","camellia128","camellia192","camellia256","chacha20",
  "chacha20-poly1305","des-ede","des-ede-cbc","des-ede-cfb","des-ede-ecb","des-ede-ofb","des-ede3",
  "des-ede3-cbc","des-ede3-cfb","des-ede3-cfb1","des-ede3-cfb8","des-ede3-ecb","des-ede3-ofb",
  "des3","des3-wrap","id-aes128-CCM","id-aes128-GCM","id-aes128-wrap","id-aes128-wrap-pad",
  "id-aes192-CCM","id-aes192-GCM","id-aes192-wrap","id-aes192-wrap-pad","id-aes256-CCM","id-aes256-GCM",
  "id-aes256-wrap","id-aes256-wrap-pad","id-smime-alg-CMS3DESwrap","sm4","sm4-cbc","sm4-cfb","sm4-ctr",
  "sm4-ecb","sm4-ofb"
};

namespace {
constexpr const char* kSrc = R"JS(
  (function(alg, keyAB, ivAB, plain){
    const crypto = require('crypto');
    const key = Buffer.from(keyAB);
    const iv  = Buffer.from(ivAB);
    try {
      const c = crypto.createCipheriv(alg, key, iv);
      let enc = c.update(plain, 'utf8', 'hex'); enc += c.final('hex');
      const d = crypto.createDecipheriv(alg, key, iv);
      let out = d.update(enc, 'hex', 'utf8'); out += d.final('utf8');
      return out;
    } catch (e) {}
  })
)JS";
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  const size_t len0 = fdp.ConsumeIntegralInRange<size_t>(0, 4096);
  const std::string a0 = fdp.ConsumeRandomLengthString(len0);
  const size_t len1 = fdp.ConsumeIntegralInRange<size_t>(0, 4096);
  const std::string a1 = fdp.ConsumeRandomLengthString(len1);
  const size_t len2 = fdp.ConsumeIntegralInRange<size_t>(0, 4096);
  const std::string a2 = fdp.ConsumeRandomLengthString(len2);
  const std::string a3 = fdp.ConsumeRemainingBytesAsString();

  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;

  const std::string js = FormatJs(
      "try { ({0})({1},{2},{3},{4}); } catch (e) {}",
      std::string(kSrc),
      ToSingleQuotedJsLiteral(a0),
      ToSingleQuotedJsLiteral(a1),
      ToSingleQuotedJsLiteral(a2),
      ToSingleQuotedJsLiteral(a3));
  fuzz::RunEnvString(iso.isolate(), js.c_str());
  return 0;
}
