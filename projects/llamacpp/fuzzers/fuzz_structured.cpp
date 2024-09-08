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
#include <string>
#include <vector>

#include <setjmp.h>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <string.h>

jmp_buf fuzzing_jmp_buf;

#define NUM_OVERRIDES 75
struct llama_model_kv_override fuzz_kv_overrides[NUM_OVERRIDES + 1];

llama_model_kv_override_type arrayed_enums[4] = {
    LLAMA_KV_OVERRIDE_TYPE_INT, LLAMA_KV_OVERRIDE_TYPE_FLOAT,
    LLAMA_KV_OVERRIDE_TYPE_BOOL, LLAMA_KV_OVERRIDE_TYPE_STR};

std::vector<std::string> possible_keys = {
    "general.type",
    "general.quantization_version",
    "general.alignment",
    "general.name",
    "general.author",
    "general.version",
    "general.url",
    "general.description",
    "general.license",
    "general.source.url",
    "general.source.huggingface.repository",
    "split.no",
    "split.count",
    "split.tensors.count",
    "tokenizer.ggml.model",
    "tokenizer.ggml.pre",
    "tokenizer.ggml.tokens",
    "tokenizer.ggml.token_type",
    "tokenizer.ggml.token_type_count",
    "tokenizer.ggml.scores",
    "tokenizer.ggml.merges",
    "tokenizer.ggml.bos_token_id",
    "tokenizer.ggml.eos_token_id",
    "tokenizer.ggml.unknown_token_id",
    "tokenizer.ggml.seperator_token_id",
    "tokenizer.ggml.padding_token_id",
    "tokenizer.ggml.cls_token_id",
    "tokenizer.ggml.mask_token_id",
    "tokenizer.ggml.add_bos_token",
    "tokenizer.ggml.add_eos_token",
    "tokenizer.ggml.add_space_prefix",
    "tokenizer.ggml.remove_extra_whitespaces",
    "tokenizer.ggml.precompiled_charsmap",
    "tokenizer.huggingface.json",
    "tokenizer.rwkv.world",
    "tokenizer.ggml.prefix_token_id",
    "tokenizer.ggml.suffix_token_id",
    "tokenizer.ggml.middle_token_id",
    "tokenizer.ggml.eot_token_id",
    "tokenizer.ggml.eom_token_id",
    "adapter.type",
    "adapter.lora.alpha",

};

std::vector<std::string> possible_architectures = {
    "llama",        "falcon",   "grok",      "gpt2",   "gptj",  "gptneox",
    "mpt",          "baichuan", "starcoder", "refact", "bert",  "nomic-bert",
    "jina-bert-v2", "bloom",    "stablelm",  "qwen",   "qwen2",
};

std::vector<std::string> possible_prefix_keys = {
    ".vocab_size",
    ".context_length",
    ".embedding_length",
    ".block_count",
    ".leading_dense_block_count",
    ".feed_forward_length",
    ".expert_feed_forward_length",
    ".expert_shared_feed_forward_length",
    ".use_parallel_residual",
    ".tensor_data_layout",
    ".expert_count",
    ".expert_used_count",
    ".expert_shared_count",
    ".expert_weights_scale",
    ".pooling_type",
    ".logit_scale",
    ".decoder_start_token_id",
    ".attn_logit_softcapping",
    ".final_logit_softcapping",
    ".rescale_every_n_layers",
    ".time_mix_extra_dim",
    ".time_decay_extra_dim",
    ".attention.head_count",
    ".attention.head_count_kv",
    ".attention.max_alibi_bias",
    ".attention.clamp_kqv",
    ".attention.key_length",
    ".attention.value_length",
    ".attention.layer_norm_epsilon",
    ".attention.layer_norm_rms_epsilon",
    ".attention.causal",
    ".attention.q_lora_rank",
    ".attention.kv_lora_rank",
    ".attention.relative_buckets_count",
    ".attention.sliding_window",
    ".rope.dimension_count",
    ".rope.freq_base",
    ".rope.scale_linear",
    ".rope.scaling.type",
    ".rope.scaling.factor",
    ".rope.scaling.attn_factor",
    ".rope.scaling.original_context_length",
    ".rope.scaling.finetuned",
    ".rope.scaling.yarn_log_multiplier",
    ".ssm.conv_kernel",
    ".ssm.inner_size",
    ".ssm.state_size",
    ".ssm.time_step_rank",
    ".ssm.dt_b_c_rms",
    ".wkv.head_size",
};

extern "C" void __wrap_abort(void) { longjmp(fuzzing_jmp_buf, 1); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 256) {
    return 0;
  }
  llama_backend_init();
  FuzzedDataProvider fdp(data, size);

  auto params = llama_model_params{};
  memset(&params, 0x0, sizeof(struct llama_model_params));
  params.use_mmap = false;
  params.progress_callback = [](float progress, void *ctx) {
    (void)ctx;
    return progress > 0.50;
  };

  int overwrite_idx = 0;

  // set the architecture
  std::string arch_key = "general.architecture";
  uint8_t arch_index =
      fdp.ConsumeIntegralInRange<uint8_t>(0, possible_architectures.size() - 1);

  std::string arch_val = std::string(possible_architectures[arch_index]);
  fuzz_kv_overrides[overwrite_idx].tag = LLAMA_KV_OVERRIDE_TYPE_STR;
  strcpy(fuzz_kv_overrides[overwrite_idx].key, arch_key.c_str());
  strcpy(fuzz_kv_overrides[overwrite_idx].val_str, arch_val.c_str());
  overwrite_idx++;

  for (int i = 0; i < possible_prefix_keys.size(); i++) {
    std::string key;
    std::string val;

    // Get the key
    key = arch_val + possible_prefix_keys[i];
    val = fdp.ConsumeRandomLengthString(32);

    // Copy the data into the overrides array
    fuzz_kv_overrides[overwrite_idx].tag = fdp.PickValueInArray(arrayed_enums);
    strcpy(fuzz_kv_overrides[overwrite_idx].key, key.c_str());
    strcpy(fuzz_kv_overrides[overwrite_idx].val_str, val.c_str());
    overwrite_idx++;
  }

  // Create the model
  std::string model_payload = fdp.ConsumeRandomLengthString();
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

  // Override an arbitrary set of arguments
  for (int i = overwrite_idx; i < NUM_OVERRIDES; i++) {
    std::string key;
    std::string val;

    // Get the key
    if (fdp.ConsumeProbability<float>() > 0.90) {
      key = fdp.ConsumeRandomLengthString(20);
    } else {
      int i = fdp.ConsumeIntegralInRange<int>(0, possible_keys.size() - 1);
      key = possible_keys[i];
    }
    val = fdp.ConsumeRandomLengthString(30);

    // Copy the data into the overrides array
    fuzz_kv_overrides[i].tag = fdp.PickValueInArray(arrayed_enums);
    strcpy(fuzz_kv_overrides[i].key, key.c_str());
    strcpy(fuzz_kv_overrides[i].val_str, val.c_str());
  }

  // For debugging
  // std::cout << "--- overwrote ---\n";
  // for (int m = 0; m < NUM_OVERRIDES-1; m++) {
  //  std::cout << "===  " << fuzz_kv_overrides[m].key << "\n";
  //}
  // std::cout << "#############\n";

  params.kv_overrides =
      (const struct llama_model_kv_override *)fuzz_kv_overrides;

  if (setjmp(fuzzing_jmp_buf) == 0) {
    auto *model = llama_load_model_from_file(filename, params);
    if (model != nullptr) {
      llama_free_model(model);
    }
  }
  llama_backend_free();

  // close any open descriptors.
  for (int i = 3; i < 1024; i++) {
    close(i);
  }

  unlink(filename);
  return 0;
}
