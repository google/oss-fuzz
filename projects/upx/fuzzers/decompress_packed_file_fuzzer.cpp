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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/conf.h"
#include "../src/file.h"
#include "../src/packmast.h"

enum OpenMode { RO_MUST_EXIST, WO_MUST_EXIST_TRUNCATE, WO_MUST_CREATE, WO_CREATE_OR_TRUNCATE };

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  char infilename[256];
  char outfilename[256];
  snprintf(infilename, 256, "/tmp/libfuzzer.%d", getpid());
  snprintf(outfilename, 256, "/tmp/libfuzzer.%d.decompressed", getpid());
  
  FILE *fp = fopen(infilename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  char argv_progname[4] = "upx";
  char argv_decompression[3] = "-d";
  char argv_output[3] = "-o";

  char* argv_data[] = {argv_progname, argv_decompression, infilename, argv_output, outfilename};

  try {
    upx_main(5, argv_data);
  } catch(...) {
  }
  
  unlink(infilename);
  unlink(outfilename);
  return 0;
}
