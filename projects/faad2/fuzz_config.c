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
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "neaacdec.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  unsigned char* non_const_data = (unsigned char *)malloc(size);
  memcpy(non_const_data, data, size);
  mp4AudioSpecificConfig mp4ASC;

  NeAACDecAudioSpecificConfig(non_const_data, (unsigned long) size, &mp4ASC);
  free(non_const_data);

  return 0;
}
