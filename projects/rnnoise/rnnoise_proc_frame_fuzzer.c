// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#include "rnnoise.h"
#include "fuzzer_temp_file.h"

#define FRAME_SIZE 480

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* filename = fuzzer_get_tmpfile(data, size);
    if (filename == NULL) {
      return 0;
    }

    int i;
    int first = 1;
    float x[FRAME_SIZE];
    FILE *f1;
    DenoiseState *st;
    st = rnnoise_create(NULL);
    f1 = fopen(filename, "r");

    while(1) {
      short tmp[FRAME_SIZE];
      fread(tmp, sizeof(short), FRAME_SIZE, f1);
      if (feof(f1)) break;
      for (i=0; i<FRAME_SIZE;i++) x[i] = tmp[i];
      rnnoise_process_frame(st, x, x);
    }
    rnnoise_destroy(st);
    fclose(f1);
    return 0;
}
