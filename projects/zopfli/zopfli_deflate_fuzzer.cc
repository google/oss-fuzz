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

#include <string>

#include "deflate.h"
#include "zopfli.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ZopfliOptions options;
  ZopfliInitOptions(&options);

  FuzzedDataProvider stream(data, size);

  // From documentation: valid values for btype are 0, 1, or 2.
  const int btype = stream.PickValueInArray({0, 1, 2});
  // The final parameter is an int but it is used as a bool.
  const int is_final = stream.ConsumeIntegralInRange(0, 1);
  const std::string input = stream.ConsumeRemainingBytesAsString();

  unsigned char* out = nullptr;
  size_t outsize = 0;
  unsigned char bp = 0;  // Apparently must be zero.
  ZopfliDeflate(&options, btype, is_final,
                reinterpret_cast<const unsigned char*>(input.data()),
                input.size(), &bp, &out, &outsize);

  if (out != nullptr) {
    free(out);
  }

  return 0;
}
