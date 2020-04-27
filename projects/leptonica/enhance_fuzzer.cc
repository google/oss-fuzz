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
        if(size<3) return 0;
        PIX *pix, *pix0, *pix1, *pix2, *pix3, *pix4;

        pix = pixReadMem(data, size);
        if(pix==NULL) return 0;
        
        pix0 = pixModifyHue(NULL, pix, 0.01 + 0.05 * 1);
        pix1 = pixModifySaturation(NULL, pix, -0.9 + 0.1 * 1);
        pix2 = pixMosaicColorShiftRGB(pix, -0.1, 0.0, 0.0, 0.0999, 1);
        pix3 = pixMultConstantColor(pix, 0.7, 0.4, 1.3);
        pix4 = pixUnsharpMasking(pix, 3, 0.01 + 0.15 * 1);

        pixDestroy(&pix);
        pixDestroy(&pix0);
        pixDestroy(&pix1);
        pixDestroy(&pix2);
        pixDestroy(&pix3);
        pixDestroy(&pix4);
        return 0;	
}
