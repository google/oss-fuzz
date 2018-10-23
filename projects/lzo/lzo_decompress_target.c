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

/* Work-memory needed for compression. Allocate memory in units
 * of 'lzo_align_t' (instead of 'char') to make sure it is properly aligned.
 */
#define HEAP_ALLOC(var,size) \
    lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);

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

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int r;
    lzo_uint new_len;
    if (size < 2){
        return 0;
    }
    /* We want to compress the data block at 'in' with length 'IN_LEN' to
     * the block at 'out'. Because the input block may be incompressible,
     * we must provide a little more output space in case that compression
     * is not possible.
    */
    unsigned char __LZO_MMODEL out[size];

    static bool isInit = false;
    if (!isInit)
    {
        if (lzo_init() != LZO_E_OK)
        {
            printf("internal error - lzo_init() failed !!!\n");
            return 0;
        }
        isInit = true;
    }

    /* Decompress. */
    int idx = data[0] % NUM_DECOMP;
    new_len = size;
    r = (*funcArr[idx])(&data[1],size-1,out,&new_len,NULL);
    if (r != LZO_E_OK)
    {
        printf("error thrown by lzo1x_decompress_safe: %d\n", r);
    }
    printf("decompressed %lu bytes back into %lu bytes\n",
            (unsigned long) size, (unsigned long) new_len);
    return 0;
}
