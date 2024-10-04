// Copyright 2024 Google LLC
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

#include "Poco/JWT/Token.h"
#include "Poco/JWT/Signer.h"

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  Poco::Crypto::initializeCrypto();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const std::string input(reinterpret_cast<const char *>(data), size);

  Poco::JWT::Signer signer;
  signer.addAllAlgorithms();
  signer.setHMACKey("secret");

  try {
    // verify untrusted input
    Poco::JWT::Token token;
    token = signer.verify(input);
  } catch (const Poco::Exception &) {
  }

  for (const auto &algorithm : signer.getAlgorithms()) {
    try {
      // sign and verify again
      Poco::JWT::Token token(input);
      token.setAudience(token.getAudience());
      signer.sign(token, algorithm);
      token = signer.verify(token.toString());
    } catch (const Poco::Exception &) {
    }
  }

  return 0;
}
