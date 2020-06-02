/*  Copyright 2020 Google Inc.

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

#include <string>

#include <libraw.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Input less than 10mb
  if (size > 10000000) {
    return 0;
  }

  LibRaw lib_raw;

  int result = lib_raw.open_buffer(
      const_cast<char*>(reinterpret_cast<const char*>(data)), size);
  if (result != LIBRAW_SUCCESS) {
    return 0;
  }

  result = lib_raw.unpack();
  if (result != LIBRAW_SUCCESS) {
    return 0;
  }

  result = lib_raw.dcraw_process();
  if (result != LIBRAW_SUCCESS) {
    return 0;
  }

  return 0;
}
