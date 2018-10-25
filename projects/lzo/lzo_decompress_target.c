/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "lzo1b.h"
#include "lzo1c.h"
#include "lzo1f.h"
#include "lzo1x.h"
#include "lzo1y.h"
#include "lzo1z.h"
#include "lzo2a.h"

typedef int (*decompress_function)( const lzo_bytep, lzo_uint  ,
                                lzo_bytep, lzo_uintp,
                                lzo_voidp  );

#define NUM_DECOMP   7

static decompress_function funcArr[NUM_DECOMP] =
{
        &lzo1b_decompress_safe,
        &lzo1c_decompress_safe,
        &lzo1f_decompress_safe,
        &lzo1x_decompress_safe,
        &lzo1y_decompress_safe,
        &lzo1z_decompress_safe,
        &lzo2a_decompress_safe
};

/* lzo (de)compresses data in blocks. Block size is the
 * size of one such block. This size has a default value of 256KB.
 */
static const size_t bufSize = 256 * 1024L;

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int r;
    lzo_uint new_len;
    if (size < 1){
        return 0;
    }
    /* Buffer into which compressed data provided by the fuzzer
     * is going to be decompressed. The buffer size is chosen
     * to be equal to the default block size (256KB) for
     * (de)compression.
     */
    unsigned char __LZO_MMODEL out[bufSize];

    static bool isInit = false;
    if (!isInit)
    {
        if (lzo_init() != LZO_E_OK)
        {
#ifdef __DEBUG__
            printf("internal error - lzo_init() failed !!!\n");
#endif
            return 0;
        }
        isInit = true;
    }

    // Decompress.
    int idx = size % NUM_DECOMP;
    new_len = bufSize;
    // Work memory not necessary for decompression
    r = (*funcArr[idx])(data, size, out, &new_len, /*wrkmem=*/NULL);
#ifdef __DEBUG__
    if (r != LZO_E_OK)
    {
        printf("error thrown by lzo1x_decompress_safe: %d\n", r);
    }
    printf("decompressed %lu bytes back into %lu bytes\n",
            (unsigned long) size, (unsigned long) new_len);
#endif
    return 0;
}
