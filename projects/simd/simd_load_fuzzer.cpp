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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "Test/TestUtils.h"

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
  if (size<5) {
    return 0;
  }
  Test::View::Format formats[4] = {Test::View::Gray8,
                                   Test::View::Bgr24,
                                   Test::View::Bgra32,
                                   Test::View::Rgb24};
  for(int i=0; i<4; i++) {
    Test::View dst1;
    dst1.Load(data, size, formats[i]);
  }
  return 0;
}
