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

// Input: a serialized Keyset proto (public keys only pass ValidateNoSecret).
// Exercises: Keyset ParseFromString, ValidateNoSecret, GetEntriesFromKeyset,
// CreateEntry -> ParseKeyWithLegacyFallback for every registered key type.
#include <cstddef>
#include <cstdint>
#include <string>

#include "tink/aead/aead_config.h"
#include "tink/daead/deterministic_aead_config.h"
#include "tink/hybrid/hpke_config.h"
#include "tink/hybrid/hybrid_config.h"
#include "tink/jwt/jwt_mac_config.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/hybrid_encrypt.h"
#include "tink/keyderivation/key_derivation_config.h"
#include "tink/mac/mac_config.h"
#include "tink/prf/prf_config.h"
#include "tink/proto_keyset_format.h"
#include "tink/public_key_verify.h"
#include "tink/signature/signature_config.h"
#include "tink/streamingaead/streaming_aead_config.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool init = []() {
    crypto::tink::MacConfig::Register().IgnoreError();
    crypto::tink::AeadConfig::Register().IgnoreError();
    crypto::tink::DeterministicAeadConfig::Register().IgnoreError();
    crypto::tink::PrfConfig::Register().IgnoreError();
    crypto::tink::SignatureConfig::Register().IgnoreError();
    crypto::tink::HybridConfig::Register().IgnoreError();
    crypto::tink::RegisterHpke().IgnoreError();
    crypto::tink::JwtMacRegister().IgnoreError();
    crypto::tink::JwtSignatureRegister().IgnoreError();
    crypto::tink::StreamingAeadConfig::Register().IgnoreError();
    crypto::tink::KeyDerivationConfig::Register().IgnoreError();
    return true;
  }();
  (void)init;

  absl::string_view input(reinterpret_cast<const char*>(data), size);
  auto handle =
      crypto::tink::ParseKeysetWithoutSecretFromProtoKeysetFormat(input);
  if (handle.ok()) {
    // Exercise primitive creation on the parsed handle (public-only).
    handle->GetPrimitive<crypto::tink::PublicKeyVerify>(
                crypto::tink::ConfigGlobalRegistry())
        .status()
        .IgnoreError();
    handle->GetPrimitive<crypto::tink::HybridEncrypt>(
                crypto::tink::ConfigGlobalRegistry())
        .status()
        .IgnoreError();
  }
  return 0;
}
