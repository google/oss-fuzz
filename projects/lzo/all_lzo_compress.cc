// Copyright 2019 Google LLC
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

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>

#include "lzo1.h"
#include "lzo1a.h"
#include "lzo1b.h"
#include "lzo1c.h"
#include "lzo1f.h"
#include "lzo1x.h"
#include "lzo1y.h"
#include "lzo1z.h"
#include "lzo2a.h"
#include "lzoconf.h"

namespace {

struct LzoAlgorithm {
  enum class Category { LZO1, LZO2 };
  enum class Type {
    LZO1,
    LZO1A,
    LZO1B,
    LZO1C,
    LZO1F,
    LZO1X,
    LZO1Y,
    LZO1Z,
    LZO2A
  };

  constexpr LzoAlgorithm(Category category, Type type, int compression_level,
                         int memory_level, lzo_compress_t compress_fn,
                         lzo_decompress_t decompress_fn,
                         size_t working_memory_size)
      : category(category),
        type(type),
        compression_level(compression_level),
        memory_level(memory_level),
        compress_fn(compress_fn),
        decompress_fn(decompress_fn),
        working_memory_size(working_memory_size) {}

  size_t GetMaxCompressedSize(size_t size) const {
    // Formula taken from the LZO FAQ.
    switch (category) {
      case Category::LZO1:
        return size + (size / 16) + 64 + 3;
      case Category::LZO2:
        return size + (size / 8) + 128 + 3;
    }
  }

  Category category;
  Type type;
  int compression_level;
  int memory_level;

  lzo_compress_t compress_fn;
  lzo_decompress_t decompress_fn;
  size_t working_memory_size;
};

static const std::vector<std::vector<LzoAlgorithm>>& GetLzoAlgorithms() {
  static auto* algorithms = new std::vector<std::vector<LzoAlgorithm>>{
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1,
                       0, 0, lzo1_compress, lzo1_decompress, LZO1_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1,
                       99, 0, lzo1_99_compress, lzo1_decompress,
                       LZO1_99_MEM_COMPRESS),
      },
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1A,
                       0, 0, lzo1a_compress, lzo1a_decompress,
                       LZO1A_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1A,
                       99, 0, lzo1a_99_compress, lzo1a_decompress,
                       LZO1A_99_MEM_COMPRESS),
      },
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       1, 0, lzo1b_1_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       2, 0, lzo1b_2_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       3, 0, lzo1b_3_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       4, 0, lzo1b_4_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       5, 0, lzo1b_5_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       6, 0, lzo1b_6_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       7, 0, lzo1b_7_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       8, 0, lzo1b_8_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       9, 0, lzo1b_9_compress, lzo1b_decompress,
                       LZO1B_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       99, 0, lzo1b_99_compress, lzo1b_decompress,
                       LZO1B_99_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1B,
                       999, 0, lzo1b_999_compress, lzo1b_decompress,
                       LZO1B_999_MEM_COMPRESS),
      },
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1C,
                       1, 0, lzo1c_1_compress, lzo1c_decompress,
                       LZO1C_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1C,
                       5, 0, lzo1c_5_compress, lzo1c_decompress,
                       LZO1C_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1C,
                       9, 0, lzo1c_9_compress, lzo1c_decompress,
                       LZO1C_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1C,
                       99, 0, lzo1c_99_compress, lzo1c_decompress,
                       LZO1C_99_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1C,
                       999, 0, lzo1c_999_compress, lzo1c_decompress,
                       LZO1C_999_MEM_COMPRESS),
      },
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1F,
                       1, 0, lzo1f_1_compress, lzo1f_decompress,
                       LZO1F_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1F,
                       999, 0, lzo1f_999_compress, lzo1f_decompress,
                       LZO1F_999_MEM_COMPRESS),
      },
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1X,
                       1, 0, lzo1x_1_compress, lzo1x_decompress,
                       LZO1X_1_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1X,
                       1, 11, lzo1x_1_11_compress, lzo1x_decompress,
                       LZO1X_1_11_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1X,
                       1, 12, lzo1x_1_12_compress, lzo1x_decompress,
                       LZO1X_1_12_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1X,
                       1, 15, lzo1x_1_15_compress, lzo1x_decompress,
                       LZO1X_1_15_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1X,
                       999, 0, lzo1x_999_compress, lzo1x_decompress,
                       LZO1X_999_MEM_COMPRESS),
      },
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1Y,
                       1, 0, lzo1y_1_compress, lzo1y_decompress,
                       LZO1Y_MEM_COMPRESS),
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1Y,
                       999, 0, lzo1y_999_compress, lzo1y_decompress,
                       LZO1Y_999_MEM_COMPRESS),
      },
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO1, LzoAlgorithm::Type::LZO1Z,
                       999, 0, lzo1z_999_compress, lzo1z_decompress,
                       LZO1Z_999_MEM_COMPRESS),
      },
      {
          LzoAlgorithm(LzoAlgorithm::Category::LZO2, LzoAlgorithm::Type::LZO2A,
                       999, 0, lzo2a_999_compress, lzo2a_decompress,
                       LZO2A_999_MEM_COMPRESS),
      },
  };
  return *algorithms;
}

void FuzzLzoAlgorithm(const LzoAlgorithm& algorithm,
                      const std::vector<uint8_t>& input_buffer) {
  std::unique_ptr<uint8_t[]> working_buffer(
      new uint8_t[algorithm.working_memory_size]);
  std::unique_ptr<uint8_t[]> compressed_buffer(
      new uint8_t[algorithm.GetMaxCompressedSize(input_buffer.size())]);

#if MEMORY_SANITIZER
  __msan_unpoison(working_buffer.get(), algorithm.working_memory_size);
#endif

  lzo_uint compressed_size;
  if (algorithm.compress_fn(input_buffer.data(), input_buffer.size(),
                            compressed_buffer.get(), &compressed_size,
                            working_buffer.get()) != LZO_E_OK) {
    abort();
  }

  std::unique_ptr<uint8_t[]> decompressed_buffer(
      new uint8_t[input_buffer.size()]);
  lzo_uint decompressed_size;
  if (algorithm.decompress_fn(compressed_buffer.get(), compressed_size,
                              decompressed_buffer.get(), &decompressed_size,
                              nullptr) != LZO_E_OK) {
    abort();
  }

  if (decompressed_size != input_buffer.size()) {
    fprintf(stderr, "Decompressed size %zu does not match original size %zu.\n",
            decompressed_size, input_buffer.size());
    abort();
  } else if (memcmp(input_buffer.data(), decompressed_buffer.get(),
                    input_buffer.size()) != 0) {
    fprintf(stderr,
            "Decompressed buffer does not match original buffer of size %zu.\n",
            input_buffer.size());
    abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool initialized __attribute__((unused)) = []() {
    if (lzo_init() != LZO_E_OK) {
      abort();
    }
    return true;
  }();

  FuzzedDataProvider data_provider(data, size);
  const auto& algorithms = GetLzoAlgorithms();
  const auto first_level_index =
      data_provider.ConsumeIntegralInRange<size_t>(0, algorithms.size() - 1);
  const auto& algorithm_group = algorithms[first_level_index];
  const auto second_level_index = data_provider.ConsumeIntegralInRange<size_t>(
      0, algorithm_group.size() - 1);
  const std::vector<uint8_t> input_buffer =
      data_provider.ConsumeRemainingBytes<uint8_t>();
  FuzzLzoAlgorithm(algorithm_group[second_level_index], input_buffer);
  return 0;
}
