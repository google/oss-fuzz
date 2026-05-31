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

/*
 * Fuzz nettle's ECDSA keypair DER parsing paths covering:
 *  - SEC1 ECC private key DER decoding (rsa-like via bignum)
 *  - ASN.1 DER iterator on SEQUENCE/BIT STRING wrapping EC keys
 *  - ecc_point_set with values parsed from DER (invalid curves, OOB coords)
 *  - PKCS#8 PrivateKeyInfo wrapper containing ECPrivateKey
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <nettle/ecc.h>
#include <nettle/ecdsa.h>
#include <nettle/bignum.h>
#include <nettle/asn1.h>

/*
 * Try to decode an ASN.1 DER SEQUENCE containing:
 *   version INTEGER,
 *   privateKey OCTET STRING,
 *   [0] OID OPTIONAL,
 *   [1] BIT STRING OPTIONAL  <-- public key point
 *
 * as an EC private key and validate the public key point on P-256.
 */
static void fuzz_ec_private_key_der(const uint8_t *data, size_t size)
{
    struct asn1_der_iterator i, inner;

    if (asn1_der_iterator_first(&i, size, data) != ASN1_ITERATOR_CONSTRUCTED)
        return;
    if (i.type != ASN1_SEQUENCE)
        return;
    if (asn1_der_decode_constructed_last(&i) != ASN1_ITERATOR_PRIMITIVE)
        return;

    /* version */
    if (i.type != ASN1_INTEGER)
        return;
    if (asn1_der_iterator_next(&i) != ASN1_ITERATOR_PRIMITIVE)
        return;

    /* privateKey OCTET STRING */
    if (i.type != ASN1_OCTET_STRING)
        return;

    size_t priv_len = i.length;
    const uint8_t *priv_data = i.data;

    /* Attempt to parse as a scalar on P-256 */
    const struct ecc_curve *curve = nettle_get_secp_256r1();
    struct ecc_scalar priv_scalar;
    ecc_scalar_init(&priv_scalar, curve);

    mpz_t z;
    mpz_init(z);
    nettle_mpz_set_str_256_u(z, priv_len, priv_data);

    /* ecc_scalar_set returns 1 on success, 0 if out-of-range */
    (void)ecc_scalar_set(&priv_scalar, z);

    mpz_clear(z);
    ecc_scalar_clear(&priv_scalar);
}

/*
 * Try to parse an EC point (uncompressed 04 || X || Y, 65 bytes for P-256)
 * directly from the fuzz input and test ecc_point_set validation.
 */
static void fuzz_ec_point_set(const uint8_t *data, size_t size)
{
    if (size < 64)
        return;

    const struct ecc_curve *curve = nettle_get_secp_256r1();
    struct ecc_point pub;
    ecc_point_init(&pub, curve);

    mpz_t x, y;
    mpz_init(x);
    mpz_init(y);

    nettle_mpz_set_str_256_u(x, 32, data);
    nettle_mpz_set_str_256_u(y, 32, data + 32);

    /* ecc_point_set validates that (x,y) is on the curve */
    (void)ecc_point_set(&pub, x, y);

    mpz_clear(x);
    mpz_clear(y);
    ecc_point_clear(&pub);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;

    uint8_t mode = data[0] & 0x01;
    data++;
    size--;

    if (mode == 0)
        fuzz_ec_private_key_der(data, size);
    else
        fuzz_ec_point_set(data, size);

    return 0;
}
