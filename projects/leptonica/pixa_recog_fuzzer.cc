/*
# Copyright 2020 Google Inc.
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

#include "string.h"
#include "allheaders.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        if(size<20) return 0;

        char filename[256];
        sprintf(filename, "/tmp/libfuzzer.pa");

        FILE *fp = fopen(filename, "wb");
        if (!fp)
                return 0;
        fwrite(data, size, 1, fp);
        fclose(fp);

        char      *text;
        l_int32    histo[10];
        PIXA      *pixa1, *pixa2, *pixa3, *pixa4;
        L_RECOG   *recog1;
        l_int32    i, n, ival;
        PIX       *pix1;

        pixa1 = pixaRead(filename);
        pixa2 = pixaCreate(0);
        pixa3 = pixaCreate(0);

        n = pixaGetCount(pixa1);
        for (i = 0; i < 10; i++)
                histo[i] = 0;
        for (i = 0; i < n; i++) {
                pix1 = pixaGetPix(pixa1, i, L_COPY);
                text = pixGetText(pix1);
                ival = text[0] - '0';
                if (ival == 4 || (ival == 7 && histo[7] == 2) ||
                        (ival == 9 && histo[9] == 2)) {
                        pixaAddPix(pixa3, pix1, L_INSERT);
                } else {
                        pixaAddPix(pixa2, pix1, L_INSERT);
                        histo[ival]++;
                }
        }

        recog1 = recogCreateFromPixa(pixa2, 0, 40, 1, 128, 1);
        pixa4 = recogTrainFromBoot(recog1, pixa3, 0.75, 128, 1);

        recogDestroy(&recog1);
        pixaDestroy(&pixa1);
        pixaDestroy(&pixa2);
        pixaDestroy(&pixa3);
        pixaDestroy(&pixa4);
        unlink(filename);

        return 0;
}
