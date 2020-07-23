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

#include "asn1_pdu.pb.h"
#include "fuzzing/proto/asn1-pdu-proto/asn1_proto_to_der.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

int FUZZ_PKCS8(const uint8_t *buf, size_t len) {
  CBS cbs;
  CBS_init(&cbs, buf, len);
  EVP_PKEY *pkey = EVP_parse_private_key(&cbs);
  if (pkey == NULL) {
    return 0;
  }

  uint8_t *der;
  size_t der_len;
  CBB cbb;
  if (CBB_init(&cbb, 0) &&
      EVP_marshal_private_key(&cbb, pkey) &&
      CBB_finish(&cbb, &der, &der_len)) {
    OPENSSL_free(der);
  }
  CBB_cleanup(&cbb);
  EVP_PKEY_free(pkey);
  ERR_clear_error();
  return 0;
}

DEFINE_PROTO_FUZZER(const asn1_pdu::PDU &asn1) {
  asn1_pdu::ASN1ProtoToDER converter = asn1_pdu::ASN1ProtoToDER();
  std::vector<uint8_t> der = converter.ProtoToDER(asn1);
  const uint8_t* ptr = &der[0];
  size_t size = der.size();
  FUZZ_PKCS8(ptr, size);
}