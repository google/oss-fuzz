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

/*
 * LibFuzzer harness for OpenLDAP BER decoding APIs
 *
 * Public APIs Used:
 *   - ber_init(struct berval *bv)
 *   - ber_peek_tag(BerElement *ber, ber_len_t *len)
 *   - ber_skip_tag(BerElement *ber, ber_len_t *len)
 *   - ber_get_int(BerElement *ber, ber_int_t *num)
 *   - ber_get_enum(BerElement *ber, ber_int_t *num)
 *   - ber_get_stringbv(BerElement *ber, struct berval *bv, int options)
 *   - ber_get_boolean(BerElement *ber, ber_int_t *boolval)
 *   - ber_get_null(BerElement *ber)
 *   - ber_scanf(BerElement *ber, const char *fmt, ...)
 *   - ber_free(BerElement *ber, int freebuf)
 *
 * Documentation Consulted:
 *   - /src/openldap/doc/man/man3/lber-decode.3
 *   - /src/openldap/include/lber.h
 *
 * Target: BER (Basic Encoding Rules) decoding functionality
 * Offline-safe: Yes (pure parsing, no network operations)
 *
 * BER is the binary encoding used by LDAP protocol. This harness tests
 * the decoder's ability to handle malformed/fuzzed BER data safely.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
#include <lber.h>
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Bound input size to prevent excessive memory usage
    // BER structures in practice are rarely huge
    if (size == 0 || size > 65536) {
        return 0;
    }

    // Create a berval structure pointing to the input data
    struct berval bv;
    bv.bv_val = (char *)data;
    bv.bv_len = size;

    // Initialize BerElement from the input data
    BerElement *ber = ber_init(&bv);
    if (ber == NULL) {
        return 0;
    }

    // Try various decode operations to exercise different code paths
    ber_tag_t tag;
    ber_len_t len;

    // 1. Peek at the tag without consuming it
    tag = ber_peek_tag(ber, &len);
    if (tag == LBER_ERROR) {
        ber_free(ber, 1);
        return 0;
    }

    // 2. Try to decode based on what tag we see
    // Reset the BerElement for fresh parsing
    // Note: ber_init() copies the data, so we must use ber_free(ber, 1) to free
    // the internal buffer that was allocated
    ber_free(ber, 1);
    ber = ber_init(&bv);
    if (ber == NULL) {
        return 0;
    }

    // Try different decode operations based on the tag class
    tag = ber_skip_tag(ber, &len);
    if (tag != LBER_ERROR) {
        ber_int_t int_val;
        struct berval str_bv;

        // Try integer decode
        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            ber_get_int(ber, &int_val);
        }

        // Try enum decode
        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            ber_get_enum(ber, &int_val);
        }

        // Try boolean decode
        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            ber_get_boolean(ber, &int_val);
        }

        // Try string decode (in-place, no allocation)
        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            memset(&str_bv, 0, sizeof(str_bv));
            ber_get_stringbv(ber, &str_bv, LBER_BV_NOTERM);
        }

        // Try string decode (with allocation)
        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            memset(&str_bv, 0, sizeof(str_bv));
            if (ber_get_stringbv(ber, &str_bv, LBER_BV_ALLOC) == LBER_ERROR) {
                // Allocation might have happened before error
            }
            if (str_bv.bv_val) {
                ber_memfree(str_bv.bv_val);
            }
        }

        // Try null decode
        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            ber_get_null(ber);
        }

        // Try ber_scanf with various format strings
        // Format specifiers from lber.h:
        // 'b' - boolean, 'e' - enum, 'i' - int, 'n' - null
        // 'o' - octet string (berval), 's' - string
        // '{' '}' - sequence, '[' ']' - set
        // 'x' - skip element

        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            // Try to decode as a simple integer
            ber_scanf(ber, "i", &int_val);
        }

        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            // Try to decode as a sequence containing an integer
            ber_scanf(ber, "{i}", &int_val);
        }

        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            // Try to skip an element
            ber_scanf(ber, "x");
        }

        ber_free(ber, 1);
        ber = ber_init(&bv);
        if (ber) {
            // Try to decode as octet string
            memset(&str_bv, 0, sizeof(str_bv));
            if (ber_scanf(ber, "o", &str_bv) != LBER_ERROR) {
                if (str_bv.bv_val) {
                    ber_memfree(str_bv.bv_val);
                }
            }
        }

        ber_free(ber, 1);
        ber = NULL;
    }

cleanup:
    if (ber) {
        ber_free(ber, 1);  // Free the internal buffer that ber_init allocated
    }

    return 0;
}
