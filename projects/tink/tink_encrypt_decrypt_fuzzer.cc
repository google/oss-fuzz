/* Copyright 2021 Google LLC
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include "tink/subtle/aes_siv_boringssl.h"


extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    crypto::tink::util::SecretData key = crypto::tink::util::SecretDataFromStringView("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    auto res = crypto::tink::subtle::AesSivBoringSsl::New(key);
    auto cipher = std::move(res.ValueOrDie());
    std::string aad = "Additional data";
    std::string message(reinterpret_cast<const char*>(data), size);
    auto ct = cipher->EncryptDeterministically(message, aad);
    auto pt = cipher->DecryptDeterministically(ct.ValueOrDie(), aad);

    return 0;
}
