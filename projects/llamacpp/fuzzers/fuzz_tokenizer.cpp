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

#include <unistd.h>

#include "common.h"
#include "llama.h"

#include <string>
#include <vector>

/*
 * Header files with model as byte arrays. These are generated using xxd.
 */
#include "model_header_aquila.h"
#include "model_header_bge.h"
#include "model_header_bpe.h"
#include "model_header_command_r.h"
#include "model_header_qwen2.h"
#include "model_header_spm.h"

#include "model_header_baichuan.h"
#include "model_header_deepseek_coder.h"
#include "model_header_falcon.h"
#include "model_header_gpt_2.h"

#include <setjmp.h>
#include <unistd.h>

llama_model *model;
llama_context *ctx;


jmp_buf fuzzing_jmp_buf;
extern "C" void __wrap_abort(void) { longjmp(fuzzing_jmp_buf, 1); }

void init() {

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d.guff", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return;
  }
#if defined(FUZZ_BGE)
  fwrite(models_ggml_vocab_bert_bge_gguf, models_ggml_vocab_bert_bge_gguf_len,
         1, fp);
#elif defined(FUZZ_SPM)
  fwrite(models_ggml_vocab_llama_spm_gguf, models_ggml_vocab_llama_spm_gguf_len,
         1, fp);
#elif defined(FUZZ_COMMAND_R)
  fwrite(models_ggml_vocab_command_r_gguf, models_ggml_vocab_command_r_gguf_len,
         1, fp);
#elif defined(FUZZ_QWEN2)
  fwrite(models_ggml_vocab_qwen2_gguf, models_ggml_vocab_qwen2_gguf_len, 1, fp);
#elif defined(FUZZ_AQUILA)
  fwrite(models_ggml_vocab_aquila_gguf, models_ggml_vocab_aquila_gguf_len, 1,
         fp);
#elif defined(FUZZ_GPT_2)
  fwrite(models_ggml_vocab_gpt_2_gguf, models_ggml_vocab_gpt_2_gguf_len, 1, fp);
#elif defined(FUZZ_BAICHUAN)
  fwrite(models_ggml_vocab_baichuan_gguf, models_ggml_vocab_baichuan_gguf_len,
         1, fp);
#elif defined(FUZZ_DEEPSEEK_CODER)
  fwrite(models_ggml_vocab_deepseek_coder_gguf,
         models_ggml_vocab_deepseek_coder_gguf_len, 1, fp);
#elif defined(FUZZ_FALCON)
  fwrite(models_ggml_vocab_falcon_gguf, models_ggml_vocab_falcon_gguf_len, 1,
         fp);
#else
  fwrite(models_ggml_vocab_llama_bpe_gguf, models_ggml_vocab_llama_bpe_gguf_len,
         1, fp);
#endif
  fclose(fp);

  llama_backend_init();

  auto mparams = llama_model_default_params();
  mparams.vocab_only = true;
  model = llama_load_model_from_file(filename, mparams);

  if (model == NULL) {
    printf("Failed to load vocab\n");
    exit(1);
  }

  auto cparams = llama_context_default_params();
  ctx = llama_new_context_with_model(model, cparams);
  if (ctx == NULL) {
    llama_free_model(model);
    exit(1);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > 4096) {
    return 0;
  }
  bool add_special = data[0] & 0x01;
  bool parse_special = data[0] & 0x01;
  uint8_t v2 = data[1];
  data += 2;
  size -= 2;

  static int initialize = 0;
  if (initialize == 0) {
    init();
    initialize = 1;
  }

  std::string payload(reinterpret_cast<const char *>(data), size);

  try {
    std::vector<llama_token> tokens =
        common_tokenize(ctx, payload.c_str(), add_special, parse_special);
    common_detokenize(ctx, tokens);

    if (setjmp(fuzzing_jmp_buf) == 0) {
      auto batch = llama_batch_get_one(tokens.data(), tokens.size());
      if (batch.n_tokens > 0) {
        llama_decode(ctx, batch);
      }
    }
  } catch (...) {
  }

  return 0;
}
