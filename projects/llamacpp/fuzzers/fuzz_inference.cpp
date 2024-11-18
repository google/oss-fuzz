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

#include "common.h"
#include "llama.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <setjmp.h>
#include <unistd.h>
#include <vector>

jmp_buf fuzzing_jmp_buf;

extern "C" void __wrap_abort(void) { longjmp(fuzzing_jmp_buf, 1); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  FuzzedDataProvider fdp(data, size);

  std::string model_payload = fdp.ConsumeRandomLengthString();
  if (model_payload.size() < 10) {
    return 0;
  }
  model_payload[0] = 'G';
  model_payload[1] = 'G';
  model_payload[2] = 'U';
  model_payload[3] = 'F';

  std::string prompt = fdp.ConsumeRandomLengthString();

  llama_backend_init();

  common_params params;
  params.prompt = prompt.c_str();
  params.n_predict = 4;

  // Create and load the model
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(model_payload.c_str(), model_payload.size(), 1, fp);
  fclose(fp);

  llama_model_params model_params = common_model_params_to_llama(params);
  model_params.use_mmap = false;

  const int n_predict = params.n_predict;
  if (setjmp(fuzzing_jmp_buf) == 0) {
    auto *model = llama_load_model_from_file(filename, model_params);
    if (model != nullptr) {

      // Now time to do inference.
      llama_context_params ctx_params =
          common_context_params_to_llama(params);
      llama_context *ctx = llama_new_context_with_model(model, ctx_params);
      if (ctx != NULL) {
          /*
        std::vector<llama_token> tokens_list;
        tokens_list = ::llama_tokenize(ctx, params.prompt, true);

        const int n_ctx = llama_n_ctx(ctx);
        const int n_kv_req =
            tokens_list.size() + (n_predict - tokens_list.size());

        if (n_kv_req <= n_ctx) {
          llama_batch batch = llama_batch_init(512, 0, 1);

          for (size_t i = 0; i < tokens_list.size(); i++) {
            llama_batch_add(batch, tokens_list[i], i, {0}, false);
          }

          // set to only output logits for last token
          batch.logits[batch.n_tokens - 1] = true;
          if (llama_decode(ctx, batch) == 0) {
            int n_cur = batch.n_tokens;
            while (n_cur <= n_predict) {
              {
                auto n_vocab = llama_n_vocab(model);
                auto *logits = llama_get_logits_ith(ctx, batch.n_tokens - 1);

                std::vector<llama_token_data> candidates;
                candidates.reserve(n_vocab);

                for (llama_token token_id = 0; token_id < n_vocab; token_id++) {
                  candidates.emplace_back(
                      llama_token_data{token_id, logits[token_id], 0.0f});
                }

                llama_token_data_array candidates_p = {
                    candidates.data(), candidates.size(), false};

                // sample the most likely token
                const llama_token new_token_id =
                    llama_sample_token_greedy(ctx, &candidates_p);

                // exit if end of generation
                if (llama_token_is_eog(model, new_token_id) ||
                    n_cur == n_predict) {
                  break;
                }

                // Prepare for next iteration
                llama_batch_clear(batch);
                llama_batch_add(batch, new_token_id, n_cur, {0}, true);
              }

              n_cur += 1;

              if (llama_decode(ctx, batch)) {
                break;
              }
            }
          }
          llama_batch_free(batch);
        }
        */
        llama_free(ctx);
      }

      llama_free_model(model);
    }
  }
  llama_backend_free();

  unlink(filename);
  return 0;
}
