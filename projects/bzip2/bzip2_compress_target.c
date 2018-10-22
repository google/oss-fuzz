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
###############################################################################
*/

#include "bzlib.h"
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

extern int BZ2_bzBuffToBuffCompress(char* dest,
                           unsigned int* destLen,
                           char*         source,
                           unsigned int  sourceLen,
                           int           blockSize100k,
                           int           verbosity,
                           int           workFactor);

extern int BZ2_bzBuffToBuffDecompress(char* dest,
                                      unsigned int* destLen,
                                      char*         source,
                                      unsigned int  sourceLen,
                                      int           small,
                                      int           verbosity);

/* Buffer size used for (de)compression.
 * The hard coded value has been borrowed from here:
 * https://github.com/google/bzip2-rpc/blob/master/unzcrash.c#L35
 * #define M_BLOCK 1000000
 *
 * #define M_BLOCK_OUT (M_BLOCK + 1000000)
 * uchar inbuf[M_BLOCK];
 * uchar outbuf[M_BLOCK_OUT];
 * uchar zbuf[M_BLOCK + 600 + (M_BLOCK / 100)];
 *
 * Legend:
 *   - inbuf: For buffereing contents read from a call to fread()
 *   - zbuf: For storing compressed output
 *   - outbuf: For storing decompressed output
 */
static const unsigned int blockSize = 1000*1000;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int r, blockSize100k, workFactor, small;
    unsigned int nZ, nOut;

    // See: https://github.com/google/bzip2-rpc/blob/master/unzcrash.c#L42
    char *zbuf = malloc(blockSize + 600 + (blockSize / 100));

    nZ = blockSize;
    blockSize100k = (size % 11) + 1;
    if (blockSize100k > 9) {
        blockSize100k = 9;
    }
    workFactor = size % 251;

    // Choose highest compression (blockSize100k=9)
    r = BZ2_bzBuffToBuffCompress(zbuf, &nZ, (char *)data, size,
            blockSize100k, /*verbosity=*/0, workFactor);
    if (r != BZ_OK) {
#ifdef __DEBUG__
        fprintf(stdout, "Compression error: %d\n", r);
#endif
        free(zbuf);
        return 0;
    }

    nOut = blockSize*2;
    char *outbuf = malloc(nOut);
    small = size % 2;
    r = BZ2_bzBuffToBuffDecompress(outbuf, &nOut, zbuf, nZ, small,
            /*verbosity=*/0);
    if (r != BZ_OK) {
#ifdef __DEBUG__
        fprintf(stdout, "Decompression error: %d\n", r);
#endif
        free(zbuf);
        free(outbuf);
        return 0;
    }

    assert(nOut == size);
    assert(memcmp(data, outbuf, size) == 0);
    free(zbuf);
    free(outbuf);
    return 0;
}