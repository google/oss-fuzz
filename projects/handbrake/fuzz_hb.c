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
#include "handbrake/handbrake.h"
#include "handbrake/hb_dict.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        char filename[256];
        sprintf(filename, "/tmp/libfuzzer.%d", getpid());

        FILE *fp = fopen(filename, "wb");
        if (!fp)
                return 0;
        fwrite(data, size, 1, fp);
        fclose(fp);

        hb_value_t *tmp = NULL;
        tmp = hb_plist_parse_file(filename);
        if (tmp != NULL) {
                hb_value_free(&tmp);
        }

        unlink(filename);

        return 0;
}

