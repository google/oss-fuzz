// Copyright 2019 Google LLC
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

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "include/zmq.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *secret_key;
  // As per API definition, input must be divisible by 5, so truncate it if it's not
  size -= size % 5;
  // As per API definition, the destination must be at least 0.8 times the input data
  secret_key = (uint8_t *)malloc(size * 4 / 5);
  if (!secret_key)
    return -1;
  std::string z85_secret_key(reinterpret_cast<const char *>(data), size);
  zmq_z85_decode(secret_key, z85_secret_key.c_str());
  free(secret_key);
  return 0;
}
