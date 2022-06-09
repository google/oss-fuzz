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

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "zopfli.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > 8192)
    return 0;

  FuzzedDataProvider stream(data, size);

  ZopfliOptions options;
  ZopfliInitOptions(&options);

  const ZopfliFormat format = stream.PickValueInArray(
      {ZOPFLI_FORMAT_GZIP, ZOPFLI_FORMAT_ZLIB, ZOPFLI_FORMAT_DEFLATE});

  unsigned char* outbuf = nullptr;
  size_t outsize = 0;
  std::vector<unsigned char> input =
      stream.ConsumeRemainingBytes<unsigned char>();

  ZopfliCompress(&options, format, input.data(), input.size(), &outbuf,
                 &outsize);

  if (outbuf != nullptr) {
    free(outbuf);
  }

  return 0;
}
