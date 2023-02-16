// Copyright 2023 Google LLC
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

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
  if (size < 4) {
    return 0;
  }

  int index = 0;
  if (data[index++] != 'H')
    return 0;

  if (data[index++] != 'e')
    return 0;

  if (data[index++] != 'l')
    return 0;

  if (size < 13) {
    return 0;
  }
  if (data[index++] != 'l')
    return 0;
  if (data[index++] != 'o')
    return 0;
  if (data[index++] != ',')
    return 0;
  if (data[index++] != ' ')
    return 0;
  if (data[index++] != 'W')
    return 0;
  if (data[index++] != 'o')
    return 0;
  if (data[index++] != 'r')
    return 0;
  if (data[index++] != 'l')
    return 0;
  if (data[index++] != 'd')
    return 0;
  if (data[index] != '!')
    return 0;

  uint8_t* x = (uint8_t *) malloc(10);
  free(x);

  return x[8];
}
