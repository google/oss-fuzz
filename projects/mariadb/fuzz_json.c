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

#include <tap.h>
#include <my_sys.h>
#include <json_lib.h>

#define FUZZ_KEY_SIZE 32

void fuzz_get_object_get(const uint8_t *data, size_t size) {
  if (size < FUZZ_KEY_SIZE) {
    return;
  }
  char *fuzz_key = malloc(FUZZ_KEY_SIZE + 1);
  memcpy(fuzz_key, data, FUZZ_KEY_SIZE);
  fuzz_key[FUZZ_KEY_SIZE] = '\0';

  data += FUZZ_KEY_SIZE;
  size -= FUZZ_KEY_SIZE;

  char *fuzz_str = malloc(size + 1);
  memcpy(fuzz_str, data, size);
  fuzz_str[size] = '\0';

  const char *value_start;
  int value_len;

  json_get_object_key(fuzz_str, fuzz_str + size, fuzz_key, &value_start,
                      &value_len);

  free(fuzz_str);
  free(fuzz_key);
}

void fuzz_json_locate_key(const uint8_t *data, size_t size) {
  if (size < FUZZ_KEY_SIZE) {
    return;
  }
  char *fuzz_key = malloc(FUZZ_KEY_SIZE + 1);
  memcpy(fuzz_key, data, FUZZ_KEY_SIZE);
  fuzz_key[FUZZ_KEY_SIZE] = '\0';

  data += FUZZ_KEY_SIZE;
  size -= FUZZ_KEY_SIZE;

  char *fuzz_str = malloc(size + 1);
  memcpy(fuzz_str, data, size);
  fuzz_str[size] = '\0';

  const char *key_start;
  const char *key_end;
  int comma_pos;

  json_locate_key(fuzz_str, fuzz_str + size, fuzz_key, &key_start, &key_end,
                  &comma_pos);

  free(fuzz_str);
  free(fuzz_key);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_get_object_get(data, size);
  fuzz_json_locate_key(data, size);
  return 0;
}
