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

#include "libbb.h"
#include "bb_archive.h"

const char *applet_name="213";

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if ((size % 4) != 0 || size < 50) {
    return 0;
  }

  unsigned int len2 = size*100;
  char *tmp2 = malloc(len2);

  lzo1x_decompress_safe(data, size, tmp2, &len2);
  free(tmp2);

  return 0;
}
