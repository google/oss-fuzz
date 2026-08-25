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

// Mode A: template proto VALIDE (params fixes) + payload fuzzé = key_value /
//         x,y / hpke public_key. The fuzzer explores the deep parse paths
//         (length checks, key creation, BoringSSL calls) without dying on the
//         proto envelope (garde-fou 1).
// Mode B: raw input = full key proto (wire-format parser coverage).
#include <cstddef>
#include <cstdint>
#include <string>

#include "proto/aes_gcm.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/hmac.pb.h"
#include "proto/hpke.pb.h"
#include "proto/ml_dsa.pb.h"
#include "proto/slh_dsa.pb.h"
#include "proto/x_aes_gcm.pb.h"
#include "tink/aead/aead_config.h"
#include "tink/daead/deterministic_aead_config.h"
#include "tink/hybrid/hpke_config.h"
#include "tink/hybrid/hybrid_config.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/jwt/jwt_mac_config.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/keyderivation/key_derivation_config.h"
#include "tink/mac/mac_config.h"
#include "tink/prf/prf_config.h"
#include "tink/restricted_data.h"
#include "tink/signature/signature_config.h"
#include "tink/streamingaead/streaming_aead_config.h"

using crypto::tink::InsecureSecretKeyAccess;
using crypto::tink::RestrictedData;
using crypto::tink::internal::KeyMaterialTypeTP;
using crypto::tink::internal::OutputPrefixTypeTP;

namespace {

struct Target {
  const char* type_url;
  KeyMaterialTypeTP kmt;
  // Builds a VALID key proto whose secret/key bytes come from `payload`.
  std::string (*build)(const std::string& payload);
};

std::string BuildHmac(const std::string& p) {
  google::crypto::tink::HmacKey k;
  k.set_version(0);
  k.mutable_params()->set_hash(google::crypto::tink::HashType::SHA256);
  k.mutable_params()->set_tag_size(32);
  k.set_key_value(p);
  return k.SerializeAsString();
}
std::string BuildAesGcm(const std::string& p) {
  google::crypto::tink::AesGcmKey k;
  k.set_version(0);
  k.set_key_value(p);
  return k.SerializeAsString();
}
std::string BuildXAesGcm(const std::string& p) {
  google::crypto::tink::XAesGcmKey k;
  k.set_version(0);
  k.mutable_params()->set_salt_size(12);
  k.set_key_value(p);
  return k.SerializeAsString();
}
std::string BuildEd25519(const std::string& p) {
  google::crypto::tink::Ed25519PublicKey k;
  k.set_version(0);
  k.set_key_value(p);
  return k.SerializeAsString();
}
std::string BuildEcdsa(const std::string& p) {
  google::crypto::tink::EcdsaPublicKey k;
  k.set_version(0);
  auto* params = k.mutable_params();
  params->set_hash_type(google::crypto::tink::HashType::SHA256);
  params->set_curve(google::crypto::tink::EllipticCurveType::NIST_P256);
  params->set_encoding(google::crypto::tink::EcdsaSignatureEncoding::IEEE_P1363);
  size_t half = p.size() / 2;
  k.set_x(p.substr(0, half));
  k.set_y(p.substr(half));
  return k.SerializeAsString();
}
std::string BuildMlDsa(const std::string& p) {
  google::crypto::tink::MlDsaPublicKey k;
  k.set_version(0);
  k.mutable_params()->set_ml_dsa_instance(
      google::crypto::tink::MlDsaInstance::ML_DSA_44);
  k.set_key_value(p);
  return k.SerializeAsString();
}
std::string BuildSlhDsa(const std::string& p) {
  google::crypto::tink::SlhDsaPublicKey k;
  k.set_version(0);
  auto* params = k.mutable_params();
  params->set_key_size(32);  // SLH-DSA-SHAKE-256f: 32-byte public key
  params->set_hash_type(google::crypto::tink::SlhDsaHashType::SHAKE);
  params->set_sig_type(google::crypto::tink::SlhDsaSignatureType::FAST_SIGNING);
  k.set_key_value(p);
  return k.SerializeAsString();
}
std::string BuildHpkeXwing(const std::string& p) {
  google::crypto::tink::HpkePublicKey k;
  k.set_version(0);
  auto* params = k.mutable_params();
  params->set_kem(google::crypto::tink::HpkeKem::X_WING);
  params->set_kdf(google::crypto::tink::HpkeKdf::HKDF_SHA256);
  params->set_aead(google::crypto::tink::HpkeAead::AES_256_GCM);
  k.set_public_key(p);
  return k.SerializeAsString();
}

const Target kStructured[] = {
    {"type.googleapis.com/google.crypto.tink.HmacKey", KeyMaterialTypeTP::kSymmetric, BuildHmac},
    {"type.googleapis.com/google.crypto.tink.AesGcmKey", KeyMaterialTypeTP::kSymmetric, BuildAesGcm},
    {"type.googleapis.com/google.crypto.tink.XAesGcmKey", KeyMaterialTypeTP::kSymmetric, BuildXAesGcm},
    {"type.googleapis.com/google.crypto.tink.Ed25519PublicKey", KeyMaterialTypeTP::kAsymmetricPublic, BuildEd25519},
    {"type.googleapis.com/google.crypto.tink.EcdsaPublicKey", KeyMaterialTypeTP::kAsymmetricPublic, BuildEcdsa},
    {"type.googleapis.com/google.crypto.tink.MlDsaPublicKey", KeyMaterialTypeTP::kAsymmetricPublic, BuildMlDsa},
    {"type.googleapis.com/google.crypto.tink.SlhDsaPublicKey", KeyMaterialTypeTP::kAsymmetricPublic, BuildSlhDsa},
    {"type.googleapis.com/google.crypto.tink.HpkePublicKey", KeyMaterialTypeTP::kAsymmetricPublic, BuildHpkeXwing},
};

// Mode B: raw protos against these critical type urls.
const char* const kRawUrls[] = {
    "type.googleapis.com/google.crypto.tink.HmacKey",
    "type.googleapis.com/google.crypto.tink.AesGcmKey",
    "type.googleapis.com/google.crypto.tink.XAesGcmKey",
    "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
    "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
    "type.googleapis.com/google.crypto.tink.MlDsaPublicKey",
    "type.googleapis.com/google.crypto.tink.SlhDsaPublicKey",
    "type.googleapis.com/google.crypto.tink.HpkePublicKey",
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
    "type.googleapis.com/google.crypto.tink.CompositeMlDsaPublicKey",
    "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey",
};

void ParseOne(const char* type_url, KeyMaterialTypeTP kmt,
              const std::string& proto) {
  auto ser = crypto::tink::internal::ProtoKeySerialization::Create(
      type_url, RestrictedData(proto, InsecureSecretKeyAccess::Get()), kmt,
      OutputPrefixTypeTP::kRaw, 42);
  if (ser.ok()) {
    crypto::tink::internal::MutableSerializationRegistry::GlobalInstance()
        .ParseKeyWithLegacyFallback(*ser, InsecureSecretKeyAccess::Get())
        .status()
        .IgnoreError();
  }
}

}  // namespace

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
  if (size == 0) return 0;

  const bool structured = (data[0] & 1) == 0;
  if (structured && size > 1) {
    // Mode A: payload -> key bytes inside a valid template.
    const Target& t = kStructured[data[0] % (sizeof(kStructured) /
                                            sizeof(kStructured[0]))];
    std::string payload(reinterpret_cast<const char*>(data + 1), size - 1);
    ParseOne(t.type_url, t.kmt, t.build(payload));
  } else {
    // Mode B: raw wire-format proto.
    std::string raw(reinterpret_cast<const char*>(data), size);
    size_t n = sizeof(kRawUrls) / sizeof(kRawUrls[0]);
    for (size_t i = 0; i < n; ++i) {
      ParseOne(kRawUrls[i], KeyMaterialTypeTP::kAsymmetricPublic, raw);
    }
  }
  return 0;
}
