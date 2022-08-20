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

#include <stdint.h>
#include <string.h>
#include "../mapserver.h"

#define kMinInputLength 10
#define kMaxInputLength 10240

void LoadMap(char *filename){

  mapObj *original_map = NULL;

  configObj *config = NULL;
  char *config_filename = NULL;
  config = msLoadConfig(config_filename);

  original_map = msLoadMap(filename, NULL,config);

  msFreeMap(original_map);
  msFreeConfig(config);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

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

  LoadMap(filename);
  unlink(filename);
  return 1;
}
