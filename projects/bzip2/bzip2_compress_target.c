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

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int r, blockSize100k, workFactor, small;
    unsigned int nZ, nOut;

    /* Copying @julian-seward1's comment from
     * https://github.com/google/oss-fuzz/pull/1887#discussion_r226852388
     *
     * They just reflect the fact that the worst case output size is 101%
     * of the input size + 600 bytes (I assume -- this is now nearly 20
     * years old). Since the buffer is in mallocville, presumably asan
     * will complain if it gets overrun. I doubt that will happen though.
     */
    nZ = size + 600 + (size / 100);
    char *zbuf = malloc(nZ);

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

    nOut = size*2;
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