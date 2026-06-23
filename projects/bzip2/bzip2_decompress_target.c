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
#include <limits.h>

extern int BZ2_bzBuffToBuffDecompress(char* dest,
                                      unsigned int* destLen,
                                      char*         source,
                                      unsigned int  sourceLen,
                                      int           small,
                                      int           verbosity);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int r, small;
    unsigned int nOut;

    // Reject inputs that would cause integer overflow in size*2
    // since nOut is unsigned int and the API uses unsigned int for sizes
    if (size > UINT_MAX / 2) {
        return 0;
    }

    // See: https://github.com/google/bzip2-rpc/blob/master/unzcrash.c#L39
    nOut = (unsigned int)(size * 2);
    char *outbuf = malloc(nOut);
    if (!outbuf) {
        return 0;
    }
    small = size % 2;
    r = BZ2_bzBuffToBuffDecompress(outbuf, &nOut, (char *)data, (unsigned int)size,
            small, /*verbosity=*/0);

    if (r != BZ_OK) {
#ifdef __DEBUG__
        fprintf(stdout, "Decompression error: %d\n", r);
#endif
    }
    free(outbuf);
    return 0;
}