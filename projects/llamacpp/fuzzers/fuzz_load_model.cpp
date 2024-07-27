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

jmp_buf fuzzing_jmp_buf;

extern "C" void __wrap_abort(void) { longjmp(fuzzing_jmp_buf, 1); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  llama_backend_init();

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  auto params = llama_model_params{};
  memset(&params, 0x0, sizeof(struct llama_model_params));
  params.use_mmap = false;
  params.progress_callback = [](float progress, void *ctx) {
    (void)ctx;
    return progress > 0.50;
  };

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
