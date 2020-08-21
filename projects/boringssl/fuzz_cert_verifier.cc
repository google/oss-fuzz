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

// This fuzz target fuzzes x509_verify_cert API found in Google/BoringSSL.

#include <openssl/stack.h>
#include <openssl/x509.h>
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "x509_certificate_chain.pb.h"
#include "x509_certificate_chain_to_der.h"

DEFINE_PROTO_FUZZER(
    const x509_certificate_chain::X509CertificateChain x509_cert_chain) {
  std::vector<std::vector<uint8_t>> encoded_x509_certs =
      X509CertificateChainToDER(x509_cert_chain);

  STACK_OF(X509) * x509_chain;

  for (std::vector<uint8_t> encoded_x509 : encoded_x509_certs) {
    const uint8_t* buf = encoded_x509.data();
    size_t size = encoded_x509.size();
    X509* x509 = d2i_X509(NULL, &buf, size);
    if (!x509) {
      return;
    }
    sk_X509_push(x509_chain, x509);
  }

  bssl::ScopedX509_STORE_CTX ctx;
  X509_STORE* verify_store;
  X509* leaf = sk_X509_value(x509_chain, 0);
  if (!X509_STORE_CTX_init(ctx.get(), verify_store, leaf, x509_chain)) {
    return;
  }

  X509_verify_cert(ctx.get());
}// Copyright 2020 Google Inc.
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

// This fuzz target fuzzes x509_verify_cert API found in Google/BoringSSL.

#include <openssl/stack.h>
#include <openssl/x509.h>
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "x509_certificate_chain.pb.h"
#include "x509_certificate_chain_to_der.h"

DEFINE_PROTO_FUZZER(
    const x509_certificate_chain::X509CertificateChain x509_cert_chain) {
  std::vector<std::vector<uint8_t>> encoded_x509_certs =
      X509CertificateChainToDER(x509_cert_chain);

  STACK_OF(X509) * x509_chain;

  for (std::vector<uint8_t> encoded_x509 : encoded_x509_certs) {
    const uint8_t* buf = encoded_x509.data();
    size_t size = encoded_x509.size();
    X509* x509 = d2i_X509(NULL, &buf, size);
    if (!x509) {
      return;
    }
    sk_X509_push(x509_chain, x509);
  }

  bssl::ScopedX509_STORE_CTX ctx;
  X509_STORE* verify_store;
  X509* leaf = sk_X509_value(x509_chain, 0);
  if (!X509_STORE_CTX_init(ctx.get(), verify_store, leaf, x509_chain)) {
    return;
  }

  X509_verify_cert(ctx.get());
}