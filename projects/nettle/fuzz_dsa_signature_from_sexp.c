// Copyright 2025 Google LLC.
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

#include <stdint.h>
#include <stddef.h>
#include <nettle/dsa.h>
#include <nettle/sexp.h>
#include <nettle/bignum.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct dsa_signature sig;
    struct sexp_iterator iter;

    dsa_signature_init(&sig);

    if (sexp_iterator_first(&iter, size, data)) {
        dsa_signature_from_sexp(&sig, &iter, 256);
    }

    dsa_signature_clear(&sig);
    return 0;
}

