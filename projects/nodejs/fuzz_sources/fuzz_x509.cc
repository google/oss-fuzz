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
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_common.h"
#include "fuzz_js_format.h"

namespace {
constexpr const char* kSrc = R"JS(
  (function(pem, email, host1, host2){
    const { X509Certificate } = require('node:crypto');
    try {
      const x = new X509Certificate(pem);
      x.checkEmail(email);
      x.checkHost(host1);
      x.checkHost(host2, { subject: 'always' });
      void x.fingerprint; void x.fingerprint512; void x.issuer; void x.subject;
    } catch (_e) {}
  })
)JS";
}

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
