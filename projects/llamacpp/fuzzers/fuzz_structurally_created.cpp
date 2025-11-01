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
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <setjmp.h>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <string.h>

jmp_buf fuzzing_jmp_buf;

enum FUZZ_LLAMA_VALUE_TYPES {
  FUZZ_STR,
  FUZZ_BOOL,
  FUZZ_INT16,
  FUZZ_UINT16,
  FUZZ_INT32,
  FUZZ_UINT32,
  FUZZ_FLOAT,
};

llama_model_kv_override_type arrayed_enums[4] = {
    LLAMA_KV_OVERRIDE_TYPE_INT, LLAMA_KV_OVERRIDE_TYPE_FLOAT,
    LLAMA_KV_OVERRIDE_TYPE_BOOL, LLAMA_KV_OVERRIDE_TYPE_STR};

std::map<std::string, FUZZ_LLAMA_VALUE_TYPES> general_map_overrides = {
    {"general.name", FUZZ_STR},
    {"split.no", FUZZ_UINT16},
    {"split.count", FUZZ_UINT16},
    {"tokenizer.ggml.model", FUZZ_STR},
    {"tokenizer.ggml.pre", FUZZ_STR}};

std::map<std::string, FUZZ_LLAMA_VALUE_TYPES> prefix_map_overrides = {
    {".vocab_size", FUZZ_UINT32},
    {".expert_count", FUZZ_UINT32},
    {".feed_forward_length", FUZZ_UINT32},
    {".expert_used_count", FUZZ_UINT32},
    {".context_length", FUZZ_UINT32},
    {".block_count", FUZZ_UINT32},
    {".embedding_length", FUZZ_UINT32},
    {".logit_scale", FUZZ_UINT32},
    {".attention.head_count", FUZZ_UINT32},
    {".leading_dense_block_count", FUZZ_UINT32},
    {".expert_feed_forward_length", FUZZ_UINT32},
    {".expert_shared_feed_forward_length", FUZZ_UINT32},
    {".use_parallel_residual", FUZZ_BOOL},
    {".expert_shared_count", FUZZ_UINT32},
    {".expert_weights_scale", FUZZ_FLOAT},
    {".decoder_start_token_id", FUZZ_UINT32},
    {".attention.layer_norm_epsilon", FUZZ_FLOAT},
    {".attention.layer_norm_rms_epsilon", FUZZ_FLOAT},
    {".attention.key_length", FUZZ_UINT32},
    {".attention.value_length", FUZZ_UINT32},
    {".attention.clamp_kqv", FUZZ_FLOAT},
    {".attention.causal", FUZZ_BOOL},
    {".attention.q_lora_rank", FUZZ_UINT32},
    {".attention.kv_lora_rank", FUZZ_UINT32},
    {".attention.relative_buckets_count", FUZZ_UINT32},
    {".rope.dimension_count", FUZZ_UINT32},
    {".attention.sliding_window", FUZZ_UINT32},
    {".rope.freq_base", FUZZ_FLOAT},
    {".rope.scale_linear", FUZZ_FLOAT},
    {".rope.scaling.type", FUZZ_STR},
    {".rope.scaling.factor", FUZZ_FLOAT},
    {".rope.scaling.attn_factor", FUZZ_FLOAT},
    {".rope.scaling.original_context_length", FUZZ_UINT32},
    {".rope.scaling.finetuned", FUZZ_BOOL},
    {".rope.scaling.yarn_log_multiplier", FUZZ_FLOAT},
    {".ssm.conv_kernel", FUZZ_UINT32},
    {".ssm.inner_size", FUZZ_UINT32},
    {".ssm.state_size", FUZZ_UINT32},
    {".ssm.time_step_rank", FUZZ_UINT32},
    {".ssm.dt_b_c_rms", FUZZ_BOOL},
    {".wkv.head_size", FUZZ_UINT32},
    {".pooling_type", FUZZ_UINT32},
    {".attn_logit_softcapping", FUZZ_FLOAT},
    {".final_logit_softcapping", FUZZ_FLOAT},
    {".rescale_every_n_layers", FUZZ_UINT32},
    {".time_mix_extra_dim", FUZZ_UINT32},
    {".time_decay_extra_dim", FUZZ_UINT32},

};

std::vector<std::string> possible_keys = {
    "general.type",
    "general.quantization_version",
    "general.alignment",
    "general.author",
    "general.version",
    "general.url",
    "general.description",
    "general.license",
    "general.source.url",
    "general.source.huggingface.repository",
    "split.tensors.count",

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

extern "C" void __wrap_abort(void) { longjmp(fuzzing_jmp_buf, 1); }

static bool create_fuzzed_gguf_file(const std::string &fname,
                                    const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  struct gguf_context *ctx = gguf_init_empty();

  std::string arch_key = "general.architecture";
  uint8_t arch_index =
      fdp.ConsumeIntegralInRange<uint8_t>(0, possible_architectures.size() - 1);

  std::string arch_val = std::string(possible_architectures[arch_index]);

  gguf_set_val_str(ctx, "general.architecture", arch_val.c_str());

  for (auto keyval : general_map_overrides) {
    if (keyval.second == FUZZ_STR) {
      uint32_t val_to_set = 0;
      if (keyval.first.find("tokenizer.ggml.model") != std::string::npos) {

        val_to_set = fdp.ConsumeIntegralInRange<uint32_t>(0, 5);
        switch (val_to_set) {
        case 0: {
          gguf_set_val_str(ctx, keyval.first.c_str(), "llama");
          break;
        }
        case 1: {
          gguf_set_val_str(ctx, keyval.first.c_str(), "bert");
          break;
        }
        case 2: {
          gguf_set_val_str(ctx, keyval.first.c_str(), "gpt2");
          break;
        }
        case 3: {
          gguf_set_val_str(ctx, keyval.first.c_str(), "t5");
          break;
        }
        case 4: {
          gguf_set_val_str(ctx, keyval.first.c_str(), "rwkv");
          break;
        }
        case 5: {
          gguf_set_val_str(ctx, keyval.first.c_str(), "no_vocab");
          break;
        }
        default:
          break;
        }
      } else {
        gguf_set_val_str(ctx, keyval.first.c_str(),
                         fdp.ConsumeRandomLengthString(32).c_str());
      }
    } else if (keyval.second == FUZZ_UINT16) {
      gguf_set_val_u16(ctx, keyval.first.c_str(),
                       fdp.ConsumeIntegral<uint16_t>());
    } else if (keyval.second == FUZZ_INT32) {
      gguf_set_val_i32(ctx, keyval.first.c_str(),
                       fdp.ConsumeIntegral<int32_t>());
    } else if (keyval.second == FUZZ_FLOAT) {
      gguf_set_val_f32(ctx, keyval.first.c_str(),
                       fdp.ConsumeFloatingPoint<float>());
    } else if (keyval.second == FUZZ_BOOL) {
      gguf_set_val_bool(ctx, keyval.first.c_str(), fdp.ConsumeBool());
    }
  }

  for (auto keyval : prefix_map_overrides) {
    std::string prefix_key = arch_val + keyval.first;

    if (keyval.second == FUZZ_STR) {
      gguf_set_val_str(ctx, prefix_key.c_str(),
                       fdp.ConsumeRandomLengthString(32).c_str());
    } else if (keyval.second == FUZZ_UINT16) {
      gguf_set_val_u16(ctx, prefix_key.c_str(),
                       fdp.ConsumeIntegral<uint16_t>());
    } else if (keyval.second == FUZZ_INT32) {
      gguf_set_val_i32(ctx, prefix_key.c_str(), fdp.ConsumeIntegral<int32_t>());
    } else if (keyval.second == FUZZ_UINT32) {
      uint32_t val_to_set = 0;
      if (prefix_key.find("expert_count") != std::string::npos) {
        val_to_set = fdp.ConsumeIntegralInRange<uint32_t>(0, 167);
      } else if (prefix_key.find("expert_used_count") != std::string::npos) {
        val_to_set = fdp.ConsumeIntegralInRange<uint32_t>(0, 3);
      } else if (prefix_key.find("block_count") != std::string::npos) {
        val_to_set = fdp.ConsumeIntegralInRange<uint32_t>(0, 128);
      } else {
        val_to_set = fdp.ConsumeIntegral<uint32_t>();
      }
      gguf_set_val_u32(ctx, prefix_key.c_str(), val_to_set);
    } else if (keyval.second == FUZZ_FLOAT) {
      gguf_set_val_f32(ctx, prefix_key.c_str(),
                       fdp.ConsumeFloatingPoint<float>());
    } else if (keyval.second == FUZZ_BOOL) {
      gguf_set_val_bool(ctx, prefix_key.c_str(), fdp.ConsumeBool());
    }
  }

  struct ggml_init_params params = {
      /*.mem_size   =*/128ull * 1024ull * 1024ull,
      /*.mem_buffer =*/NULL,
      /*.no_alloc   =*/false,
  };

  struct ggml_context *ctx_data = ggml_init(params);

  const int n_tensors = 10;

  // tensor infos
  for (int i = 0; i < n_tensors; ++i) {
    const std::string name = "tensor_" + std::to_string(i);

    int64_t ne[GGML_MAX_DIMS] = {1};
    int32_t n_dims = fdp.ConsumeIntegralInRange<int32_t>(1, GGML_MAX_DIMS);

    for (int j = 0; j < n_dims; ++j) {
      ne[j] = fdp.ConsumeIntegralInRange<int64_t>(1, 99999);
    }

    struct ggml_tensor *cur =
        ggml_new_tensor(ctx_data, GGML_TYPE_F32, n_dims, ne);
    ggml_set_name(cur, name.c_str());

    {
      float *data = (float *)cur->data;
      for (int j = 0; j < ggml_nelements(cur); ++j) {
        data[j] = 100 + i;
      }
    }

    gguf_add_tensor(ctx, cur);
  }

  gguf_write_to_file(ctx, fname.c_str(), false);

  printf("%s: wrote file '%s;\n", __func__, fname.c_str());

  ggml_free(ctx_data);
  gguf_free(ctx);

  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 256) {
    return 0;
  }
  llama_backend_init();

  auto params = llama_model_params{};
  memset(&params, 0x0, sizeof(struct llama_model_params));
  params.use_mmap = false;
  params.progress_callback = [](float progress, void *ctx) {
    (void)ctx;
    return progress > 0.50;
  };

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  create_fuzzed_gguf_file(filename, data, size);

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
