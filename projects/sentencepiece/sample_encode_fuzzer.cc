// Copyright 2020 Google LLC
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
#include <vector>

#include "sentencepiece_processor.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  sentencepiece::SentencePieceProcessor fuzz_sp_processor;
  FuzzedDataProvider data_provider(data, size);
  const int nbest_size = data_provider.ConsumeIntegral<int>();
  const float alpha = data_provider.ConsumeFloatingPoint<float>();
  const std::string in_string = data_provider.ConsumeRemainingBytesAsString();

  fuzz_sp_processor.SampleEncodeAsSerializedProto(in_string, nbest_size, alpha);
  return 0;
}
