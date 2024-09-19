/* Copyright 2024 Google LLC
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

#include "llama.h"
#include <fuzzer/FuzzedDataProvider.h>

char buf[4096];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);

  std::string p1 = fuzzed_data.ConsumeRandomLengthString();
  std::string p2 = fuzzed_data.ConsumeRandomLengthString();
  std::string p3 = fuzzed_data.ConsumeRandomLengthString();
  std::string p4 = fuzzed_data.ConsumeRandomLengthString();
  std::string p5 = fuzzed_data.ConsumeRandomLengthString();
  std::string p6 = fuzzed_data.ConsumeRandomLengthString();
  std::string p7 = fuzzed_data.ConsumeRandomLengthString();

  llama_chat_message conversation[] = {
      {"system", p2.c_str()},    {"user", p3.c_str()},
      {"assistant", p4.c_str()}, {"user", p5.c_str()},
      {"assistant", p6.c_str()}, {"user", p7.c_str()},
  };
  size_t message_count = 6;

  llama_chat_apply_template(nullptr, p1.c_str(), conversation, message_count,
                            true, buf, 4096);
  return 0;
}
