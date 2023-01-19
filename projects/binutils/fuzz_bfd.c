/* Copyright 2020 Google Inc.

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

#include "sysdep.h"
#include "bfd.h"

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static int bufferToFile(char * name, const uint8_t *Data, size_t Size) {
    int fd = mkstemp(name);
    if (fd < 0) {
        printf("failed mkstemp, errno=%d\n", errno);
        return -2;
    }
    if (write (fd, Data, Size) != Size) {
        printf("failed write, errno=%d\n", errno);
        close(fd);
        return -3;
    }
    close(fd);
    return 0;
}

//TODO? part of fuzzing
char *target = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char tmpfilename[32];

    if (bfd_init() != BFD_INIT_MAGIC)
      abort();

    strncpy(tmpfilename, "/tmp/fuzz.bfd-XXXXXX", 31);
    if (bufferToFile(tmpfilename, Data, Size) < 0) {
        return 0;
    }
    bfd *file = bfd_openr (tmpfilename, target);
    if (file == NULL)
    {
        remove(tmpfilename);
        return 0;
    }
    bfd_check_format (file, bfd_archive);
    //TODO loop over subfiles and more processing
    bfd_close (file);
    remove(tmpfilename);

    return 0;
}
