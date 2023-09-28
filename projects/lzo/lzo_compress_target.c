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
#include "lzo1x.h"

/* Work-memory needed for compression. Allocate memory in units
 * of 'lzo_align_t' (instead of 'char') to make sure it is properly aligned.
 */
#define HEAP_ALLOC(var,size) \
    lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int r;
    lzo_uint out_len;
    lzo_uint new_len;

    /* Since we allocate in/out on the stack,
     * we can't handle too large size.
     */
    if (size > (1 << 20))
        size = 1 << 20;

    /* We want to compress the data block at 'in' with length 'IN_LEN' to
     * the block at 'out'. Because the input block may be incompressible,
     * we must provide a little more output space in case that compression
     * is not possible.
    */
    unsigned char __LZO_MMODEL in[size > 0 ? size : 1];
    unsigned char __LZO_MMODEL out[size + size/16 + 64 + 3];

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

    /* Compress with LZO1X-1. */
    r = lzo1x_1_compress(data, size, out, &out_len, wrkmem);
    assert(r == LZO_E_OK);
#ifdef __DEBUG__
    printf("compressed %lu bytes into %lu bytes\n",
            (unsigned long) size, (unsigned long) out_len);
#endif
    
    /* check for an incompressible block */
    if (out_len >= size)
    {
#ifdef __DEBUG__
        printf("This block contains incompressible data.\n");
#endif
        return 0;
    }

    // Decompress
    new_len = size;
    r = lzo1x_decompress(out, out_len, in, &new_len,/*wrkmem=*/NULL);
    assert(r == LZO_E_OK && new_len == size);
#ifdef __DEBUG__
    printf("decompressed %lu bytes back into %lu bytes\n",
            (unsigned long) out_len, (unsigned long) size);
#endif
    return 0;
}
