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
#include <iostream>
#include <setjmp.h>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <string.h>

jmp_buf fuzzing_jmp_buf;

#define NUM_OVERRIDES 40
struct llama_model_kv_override fuzz_kv_overrides[NUM_OVERRIDES + 1];

llama_model_kv_override_type arrayed_enums[4] = {
    LLAMA_KV_OVERRIDE_TYPE_INT, LLAMA_KV_OVERRIDE_TYPE_FLOAT,
    LLAMA_KV_OVERRIDE_TYPE_BOOL, LLAMA_KV_OVERRIDE_TYPE_STR};

extern "C" void __wrap_abort(void) { longjmp(fuzzing_jmp_buf, 1); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  llama_backend_init();
  FuzzedDataProvider fdp(data, size);

  // Create the model
  std::string model_payload = fdp.ConsumeRemainingBytesAsString();
  if (model_payload.size() < 10) {
    return 0;
  }
  model_payload[0] = 'G';
  model_payload[1] = 'G';
  model_payload[2] = 'U';
  model_payload[3] = 'F';

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(model_payload.data(), model_payload.size(), 1, fp);
  fclose(fp);

  auto params = llama_model_params{};
  memset(&params, 0x0, sizeof(struct llama_model_params));
  params.use_mmap = false;
  params.progress_callback = [](float progress, void *ctx) {
    (void)ctx;
    return progress > 0.50;
  };

  // Override an arbitrary set of arguments
  for (int i = 0; i < NUM_OVERRIDES; i++) {
    std::string key = fdp.ConsumeRandomLengthString(64);
    std::string val = fdp.ConsumeRandomLengthString(64);

    // Copy the data into the overrides array
    fuzz_kv_overrides[i].tag = fdp.PickValueInArray(arrayed_enums);
    strcpy(fuzz_kv_overrides[i].key, key.c_str());
    strcpy(fuzz_kv_overrides[i].val_str, val.c_str());
  }

  params.kv_overrides =
      (const struct llama_model_kv_override *)fuzz_kv_overrides;

  if (setjmp(fuzzing_jmp_buf) == 0) {
    auto *model = llama_load_model_from_file(filename, params);
    if (model != nullptr) {
      llama_free_model(model);
    }
  }
  llama_backend_free();

  unlink(filename);
  return 0;
}
