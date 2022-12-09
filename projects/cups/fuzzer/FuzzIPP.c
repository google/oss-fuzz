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
#include "file.h"
#include "string-private.h"
#include "ipp-private.h"
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#define kMinInputLength 10
#define kMaxInputLength 10240

void LoadIPP(char *filename){
    cups_file_t	*fp;
    ipp_t		*request;

    request = ippNew();
    fp = cupsFileOpen(filename, "r");

    ippReadIO(fp, (ipp_iocb_t)cupsFileRead, 1, NULL, request);

    cupsFileClose(fp);
    ippDelete(request);
}

extern int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*cups/cups/fuzzipp.c*/

    if (Size < kMinInputLength || Size > kMaxInputLength){
      return 1;
    }

    char filename[256];

    sprintf(filename, "/tmp/libfuzzer.%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }

    fwrite(Data, Size, 1, fp);
    fclose(fp);

    LoadIPP(filename);
    unlink(filename);

    return 0;
}
