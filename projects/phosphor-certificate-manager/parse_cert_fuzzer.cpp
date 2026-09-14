// Copyright 2026 Google LLC
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
//##############################################################################

#include "x509_utils.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string pem(reinterpret_cast<const char*>(data), size);
    try {
        auto cert = phosphor::certs::parseCert(pem);
        if (cert) {
            // Validate start date
            phosphor::certs::validateCertificateStartDate(*cert);

            // Validate in SSL context
            phosphor::certs::validateCertificateInSSLContext(*cert);

            // Validate against an empty store.
            // Since validateCertificateAgainstStore allows trust chain errors,
            // this should not throw for typical untrusted certs, but will
            // exercise the verification logic.
            std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)> x509Store(
                X509_STORE_new(), &X509_STORE_free);
            if (x509Store) {
                phosphor::certs::validateCertificateAgainstStore(*x509Store, *cert);
            }
        }
    } catch (const std::exception& e) {
        // Catch expected exceptions to prevent the fuzzer from treating them as crashes.
    } catch (...) {
        // Catch any other unexpected exceptions.
    }
    return 0;
}
