/* Copyright 2021 Google LLC
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
#include <stdio.h>
#include <unistd.h>

#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);

    GF_ISOFile *movie = NULL;
    movie = gf_isom_open_file(filename, GF_ISOM_OPEN_READ_DUMP, NULL);
    if (movie != NULL) {
        gf_isom_close(movie);
    }
    unlink(filename);
    return 0;
}
