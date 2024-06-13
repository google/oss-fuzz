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

#include <iostream>
#include <string>
#include "lm/common/model_buffer.hh"
#include "lm/model.hh"
#include "lm/state.hh"


extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char filename[] = "/tmp/libfuzzer";

  FILE *fp = fopen(filename, "wb");
  if (!fp)
    return 0;
  fwrite(data, size, 1, fp);
  fclose(fp);

  using namespace lm::ngram;
  try {
    Model model(filename);
    State state(model.BeginSentenceState()), out_state;
    const lm::WordIndex a = model.GetVocabulary().Index("a");
  } catch (...) {}

  std::remove(filename);
  return 0;
}
