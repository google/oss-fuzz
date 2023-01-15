/* Copyright 2022 Google LLC
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
#undef _CUPS_NO_DEPRECATED
#include "cups-private.h"
#include "ppd-private.h"
#include "raster-private.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>

#define kMinInputLength 10
#define kMaxInputLength 10240

extern int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*cups/cups/testppd.c*/

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 1;
    }

/*Add Null byte*/
    char *DataFx;
    size_t SizeFx = Size+1;
    DataFx = (char *)calloc(SizeFx,sizeof(char));
    memcpy((void *)DataFx,(void *)Data,Size);

    int	preferred_bits;
    cups_page_header2_t	header;

    memset(&header, 0, sizeof(header));
    header.Collate = CUPS_TRUE;
    preferred_bits = 0;

    _cupsRasterExecPS(&header, &preferred_bits,(char*)DataFx);

    free(DataFx);
    return 0;
}
