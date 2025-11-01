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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cJSON.h"
#include "loader.h"
#include "fuzz_header.h"

/*
 * Targets the custom version of cJson.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  cJSON *json = NULL;
  loader_get_json(NULL, filename, &json);

  if (json == NULL) {
    goto out;
  }
  bool out_of_mem = false;
  char *json_data = loader_cJSON_Print(json, &out_of_mem);

  if (json_data != NULL) {
    free(json_data);
  }

  if (json != NULL) {
    loader_cJSON_Delete(json);
  }

out:
  unlink(filename);

  return 0;
}
