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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "heimbase.h"

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  char *null_terminated = (char *)malloc(size + 1);
  memcpy(null_terminated, (char *)data, size);
  null_terminated[size] = '\0';

  // Call various json handlers
  heim_error_t error = NULL;
  heim_object_t o = heim_json_create(null_terminated, 20, 0, &error);
  if (error == NULL) {
    heim_error_t error2 = NULL;
    heim_object_t o2 = heim_json_copy_serialize(o, 0, &error2);
    if (error2 == NULL) {
      heim_error_t error3 = NULL;
      heim_object_t o3 =
          heim_json_create(heim_string_get_utf8(o2), 20, 0, &error3);
      if (error3 != NULL) {
        heim_json_eq(o, o3);
      }
    }
    heim_release(o2);
  }
  heim_release(o);

  free(null_terminated);
  return 0;
}
