/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Input: bytes used as the private key seed. Fixed sizes required by the APIs;
// corpus seeds are sized accordingly. BoringSSL boundary is explicit here:
// crashes inside boringssl/ are a different project (out of scope), crashes
// inside tink/ (tink/internal/mlkem_util.cc, xwing_util.cc) are in scope.
#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/internal/mlkem_util.h"
#include "tink/internal/xwing_util.h"
#include "tink/util/secret_data.h"

using crypto::tink::internal::ML_KEM768;
using crypto::tink::internal::ML_KEM1024;
using crypto::tink::internal::MlKemKeyFromPrivateKey;
using crypto::tink::internal::XWingKeyFromPrivateKey;
using crypto::tink::util::SecretDataFromStringView;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  absl::string_view input(reinterpret_cast<const char*>(data), size);

  // ML-KEM seed: exactly 64 bytes expected (both sizes share the seed format).
  if (size >= 64) {
    auto sd = SecretDataFromStringView(input.substr(0, 64));
    MlKemKeyFromPrivateKey(sd, ML_KEM768).status().IgnoreError();
    MlKemKeyFromPrivateKey(sd, ML_KEM1024).status().IgnoreError();
  }
  // X-Wing private key: exactly 32 bytes.
  if (size >= 32) {
    auto sd = SecretDataFromStringView(input.substr(0, 32));
    XWingKeyFromPrivateKey(sd).status().IgnoreError();
  }
  return 0;
}
