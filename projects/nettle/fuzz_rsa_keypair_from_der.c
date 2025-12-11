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
#include <nettle/rsa.h>
#include <nettle/bignum.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct rsa_public_key pub;
    struct rsa_private_key priv;

    rsa_public_key_init(&pub);
    rsa_private_key_init(&priv);

    rsa_keypair_from_der(&pub, &priv, 0, size, data);

    rsa_private_key_clear(&priv);
    rsa_public_key_clear(&pub);
    return 0;
}

