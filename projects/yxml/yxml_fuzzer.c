/* Copyright 2024 Google LLC
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
#include <string.h>

#include "yxml.h"

#define BUFFER_SIZE 4096

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Initialise YXML object
  void *buf = malloc(BUFFER_SIZE);
  yxml_t xml;
  yxml_init(&xml, buf, BUFFER_SIZE);

  // Parse fuzzing data with YXML
  for (int i = 0; i < size; i++) {
    yxml_parse(&xml, data[i]);
  }

  // Clean object
  yxml_eof(&xml);
  free(buf);
  return 0;
}
