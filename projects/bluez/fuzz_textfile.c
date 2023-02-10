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
#include <config.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>

#include "src/textfile.h"


char *get_null_terminated(const uint8_t **data, size_t *size) {
#define STR_SIZE 75
  if (*size < STR_SIZE || (int)*size < 0) {
    return NULL;
  }

  char *new_s = malloc(STR_SIZE + 1);
  memcpy(new_s, *data, STR_SIZE);
  new_s[STR_SIZE] = '\0';

  *data = *data+STR_SIZE;
  *size -= STR_SIZE;
  return new_s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *data_ptr = data;
  size_t size_val = size;

  char *key1 = get_null_terminated(&data_ptr, &size_val);
  char *val1 = get_null_terminated(&data_ptr, &size_val);
  char *key2 = get_null_terminated(&data_ptr, &size_val);

  if (!key1 || !val1 || !key2) {
    goto cleanup;
  }
  // Create a file with rest of content
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data_ptr, size_val, 1, fp);
  fclose(fp);

  textfile_put(filename, key1, val1);
  textfile_get(filename, key2);

  unlink(filename);

cleanup:

  if (key1 != NULL) {
    free(key1);
    key1 = NULL;
  }
  if (val1 != NULL) {
    free(val1);
    val1 = NULL;
  }
  if (key2 != NULL) {
    free(key2);
    key2 = NULL;
  }

  return 0;
}
