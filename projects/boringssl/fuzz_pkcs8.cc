// Copyright 2020 Google Inc.
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
//
////////////////////////////////////////////////////////////////////////////////

// This fuzz target fuzzes the same API as
// https://github.com/google/boringssl/blob/master/fuzz/pkcs8.cc, but it employs
// libprotobuf-mutator for structure-aware fuzzing.

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include "asn1_pdu.pb.h"
#include "asn1_pdu_to_der.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const asn1_pdu::PDU& asn1) {
  asn1_pdu::ASN1PDUToDER converter;
  std::vector<uint8_t> encoded = converter.PDUToDER(asn1);
  const uint8_t* buf = encoded.data();
  size_t len = encoded.size();

  CBS cbs;
  CBS_init(&cbs, buf, len);
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_parse_private_key(&cbs));
  if (pkey == NULL) {
    return;
  }

  uint8_t* der;
  size_t der_len;
  bssl::ScopedCBB cbb;
  if (CBB_init(cbb.get(), 0) &&
      EVP_marshal_private_key(cbb.get(), pkey.get()) &&
      CBB_finish(cbb.get(), &der, &der_len)) {
    OPENSSL_free(der);
  }
  ERR_clear_error();
}