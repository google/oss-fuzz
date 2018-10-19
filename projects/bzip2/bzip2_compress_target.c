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
    int r;
    unsigned int nZ, nOut;
    char *zbuf = malloc(size + 600 + (size / 100));

    r = BZ2_bzBuffToBuffCompress(zbuf, &nZ, (char *)data, size, 9, 0, 30);
    if (r != BZ_OK) {
#ifdef __DEBUG__
        fprintf(stdout, "Compression error: %d\n", r);
#endif
        free(zbuf);
        return 0;
    }

    nOut = size*2;
    char *outbuf = malloc(nOut);
    r = BZ2_bzBuffToBuffDecompress(outbuf, &nOut, zbuf, nZ, 0, 0);
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