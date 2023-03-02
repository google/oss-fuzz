/* Copyright 2023 Google LLC
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

#include "hdf5.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Some old logic with regards to skipping first byte. Leaving it here
    // to avoid affecting the clusterfuzz-generated corpus.
    if (size == 0) {
        return 0;
    }
    uint8_t decider = data[0];
    size -= 1;
    data += 1;

    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);

    H5Fopen(filename, H5F_ACC_RDONLY, H5P_DEFAULT);

    return 0;
}
