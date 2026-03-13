/********************************************************************************
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *******************************************************************************/
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "zlib.h"

static Bytef buffer[256 * 1024] = { 0 };

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

  uLong basesz = size ? (--size, *data++) : 8;
  uLong multiplier0 = size ? (--size, *data++) : 1;
  uLong multiplier1 = size ? (--size, *data++) : 1;

  uLongf buffer_length = static_cast<uLongf>(basesz * multiplier0 * multiplier1);
  uLong buf_size = static_cast<uLong>(size);
  // Ignore return code.
  uncompress2(buffer, &buffer_length, data, &buf_size);
  return 0;
}
