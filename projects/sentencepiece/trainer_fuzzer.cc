// Copyright 2026 Google LLC
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
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "sentencepiece_trainer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Training is expensive, so we limit the number of sentences and their length.
  // We also limit the vocab_size.
  
  int vocab_size = fdp.ConsumeIntegralInRange<int>(10, 100);
  std::string model_type;
  switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
    case 0: model_type = "unigram"; break;
    case 1: model_type = "bpe"; break;
    case 2: model_type = "word"; break;
    case 3: model_type = "char"; break;
  }

  // We use an empty model_prefix and pass a pointer to a string to receive
  // the serialized model proto. This avoids writing to disk.
  std::string args = "--vocab_size=" + std::to_string(vocab_size) +
                     " --model_type=" + model_type;

  // Randomly add some other common flags
  if (fdp.ConsumeBool()) {
    args += " --character_coverage=" + std::to_string(fdp.ConsumeFloatingPointInRange<float>(0.98, 1.0));
  }
  if (fdp.ConsumeBool()) {
    args += " --input_sentence_size=" + std::to_string(fdp.ConsumeIntegralInRange<int>(100, 500));
  }
  if (fdp.ConsumeBool()) {
    args += " --shuffle_input_sentence=" + std::string(fdp.ConsumeBool() ? "true" : "false");
  }
  if (fdp.ConsumeBool()) {
    args += " --split_by_unicode_script=" + std::string(fdp.ConsumeBool() ? "true" : "false");
  }
  if (fdp.ConsumeBool()) {
    args += " --split_by_whitespace=" + std::string(fdp.ConsumeBool() ? "true" : "false");
  }
  if (fdp.ConsumeBool()) {
    args += " --split_by_number=" + std::string(fdp.ConsumeBool() ? "true" : "false");
  }
  if (fdp.ConsumeBool()) {
    args += " --byte_fallback=" + std::string(fdp.ConsumeBool() ? "true" : "false");
  }
  
  // Mandatory for performance in fuzzing
  args += " --num_threads=1";

  // Generate a small number of training sentences
  int num_sentences = fdp.ConsumeIntegralInRange<int>(1, 50);
  std::vector<std::string> sentences;
  for (int i = 0; i < num_sentences; ++i) {
    // Keep sentences relatively short
    std::string s = fdp.ConsumeRandomLengthString(200);
    if (!s.empty()) {
      sentences.push_back(s);
    }
  }

  // Ensure we have at least one non-empty sentence to avoid immediate 
  // failure in some trainer types that CHECK(!sentences_.empty()).
  if (sentences.empty()) {
    sentences.push_back("the quick brown fox jumps over the lazy dog");
  }

  std::string serialized_model_proto;
  // Train can return various errors for invalid combinations of parameters,
  // which is expected.
  sentencepiece::SentencePieceTrainer::Train(args, sentences, &serialized_model_proto);

  return 0;
}
