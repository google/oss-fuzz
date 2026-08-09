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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Use all remaining bytes as the message string
  const std::string message = fdp.ConsumeRemainingBytesAsString();

  // JS template to fuzz crypto signing/verifying using Node.js
  static constexpr std::string_view kTemplate = R"(
const crypto = require('crypto');

// Generate an RSA key pair (per fuzz run)
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048
});

// The fuzzed message
const message = {0};

// --- SIGNING ---
try {
  const signer = crypto.createSign('SHA256');
  signer.update(message);
  signer.end();
  const signature = signer.sign(privateKey, 'base64');

  // --- VERIFYING ---
  const verifier = crypto.createVerify('SHA256');
  verifier.update(message);
  verifier.end();
  const isValid = verifier.verify(publicKey, signature, 'base64');
} catch (e) {
  // Catch errors to prevent harness crashes
}
)";

  // Inject the fuzzed message into the JS template
  const std::string js = FormatJs(kTemplate, ToSingleQuotedJsLiteral(message));

  // Execute the JavaScript under a Node isolate
  fuzz::IsolateScope iso;
  if (!iso.ok()) return 0;
  fuzz::RunEnvString(iso.isolate(), js.c_str());

  return 0;
}
