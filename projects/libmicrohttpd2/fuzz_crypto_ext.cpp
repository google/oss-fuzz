// Copyright 2025 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <algorithm>

#include <fuzzer/FuzzedDataProvider.h>

#include "md5_ext.h"
#include "sha256_ext.h"


// Fuzzing target function pointer types for the enternal hash APIs
template <typename HashType> using InitOnceFn = void (*)(HashType*);
template <typename HashType> using UpdateFn   = void (*)(HashType*, size_t, const uint8_t*);
template <typename HashType> using FinishFn   = void (*)(HashType*, uint8_t*);
template <typename HashType> using DeinitFn   = void (*)(HashType*);

// Generic hashing flow that fuzz same hashing procedure for different algorithm
template <typename HashType>
static void fuzz_hash_ext_multi(FuzzedDataProvider &fdp,
                                size_t block_size,
                                InitOnceFn<HashType> init_once,
                                UpdateFn<HashType> update_fn,
                                FinishFn<HashType> finish_fn,
                                DeinitFn<HashType> deinit_fn,
                                size_t digest_size) {
  if (!fdp.remaining_bytes()) {
    return;
  }

  // Pull a random slice of data for fuzzing
  size_t take_len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  std::vector<uint8_t> input_bytes = fdp.ConsumeBytes<uint8_t>(take_len);

  // Create 1 to 4 independent hashing contexts with it own digest buffer
  const unsigned num_contexts = fdp.ConsumeIntegralInRange<unsigned>(1, 4);
  std::vector<HashType> contexts(num_contexts);
  std::vector<std::vector<uint8_t>> digests(num_contexts, std::vector<uint8_t>(digest_size));
  for (unsigned i = 0; i < num_contexts; i++) {
    init_once(&contexts[i]);
  }

  // Intentionally misalign the data pointer to stress alignment sensitive paths
  const size_t misalign_pad = fdp.ConsumeIntegralInRange<size_t>(0, 64);
  std::vector<uint8_t> scratch_buf(misalign_pad + input_bytes.size());
  if (!input_bytes.empty()) {
    memcpy(scratch_buf.data() + misalign_pad, input_bytes.data(), input_bytes.size());
  }

  // Define cursor and remaining bytes counter to keep track of the multiple hash update iterations
  const uint8_t *cursor = scratch_buf.data() + misalign_pad;
  size_t remaining = input_bytes.size();

  // Perform multiple hash update iterations on the raw data
  unsigned num_iterations = fdp.ConsumeIntegralInRange<unsigned>(1, 4);
  while (num_iterations-- && remaining > 0) {
    // Pick which context to feed this iteration
    const unsigned ctx_index = (num_contexts == 1) ? 0 : fdp.ConsumeIntegralInRange<unsigned>(0, num_contexts - 1);

    // Choose a chunking pattern relative to block size.
    enum Pattern { LESS1, EQ, PLUS1, SMALL, RANDOM, TAIL, HALT };
    Pattern pattern = fdp.PickValueInArray<Pattern>({LESS1, EQ, PLUS1, SMALL, RANDOM, TAIL, HALT});

    size_t chunk_len = 0;
    switch (pattern) {
      case LESS1: {
        // Consume 1 byte less from block size from the raw data for this iteration
        if (block_size > 1) {
          chunk_len = std::min(remaining, block_size - 1);
        }
        break;
      }
      case EQ: {
        // Consume block size bytes from the raw data for this iteration
        chunk_len = std::min(remaining, block_size);
        break;
      }
      case PLUS1: {
        // Consume 1 byte more from block size from the raw data for this iteration
        chunk_len = std::min(remaining, block_size + 1);
        break;
      }
      case SMALL: {
        // Consume 1~32 bytes from the raw data for this iteration
        size_t small_len = (size_t)fdp.ConsumeIntegralInRange<int>(1, 32);
        chunk_len = std::min(remaining, small_len);
        break;
      }
      case RANDOM: {
        // Consume random bytes from the raw data for this iteration
        chunk_len = (remaining >= 1) ? (size_t)fdp.ConsumeIntegralInRange<size_t>(1, remaining) : 0;
        break;
      }
      case TAIL: {
        // Consume all remaining bytes from the raw data for this iteration
        chunk_len = remaining;
        break;
      }
      case HALT: {
        // Consume small chunk and consider reinitialisation or early halt of the hash iteration
        size_t step  = std::max<size_t>(1, fdp.ConsumeIntegralInRange<size_t>(1, block_size));
        size_t loops = fdp.ConsumeIntegralInRange<size_t>(1, 4);
        for (size_t j = 0; j < loops && remaining > 0; j++) {
          size_t w = std::min(remaining, step);
          update_fn(&contexts[ctx_index], w, cursor);
          cursor += w;
          remaining -= w;
        }

        // Randomly reinitialise the hash stream
        if (fdp.ConsumeBool()) {
          finish_fn(&contexts[ctx_index], digests[ctx_index].data());
        }
        continue;
      }
    }

    if (chunk_len == 0 || chunk_len > remaining) {
      continue;
    }

    // Fuzz the update function
    update_fn(&contexts[ctx_index], chunk_len, cursor);
    cursor += chunk_len;
    remaining -= chunk_len;
  }

  // Finalize all active contexts (finish_reset).
  for (unsigned i = 0; i < num_contexts; i++) {
    finish_fn(&contexts[i], digests[i].data());
  }

  // Additional fuzzing on special context chaining approach.
  if (num_contexts >= 2 && digest_size && fdp.ConsumeBool()) {
    unsigned src_idx = fdp.ConsumeIntegralInRange<unsigned>(0, num_contexts - 1);
    unsigned dst_idx = fdp.ConsumeIntegralInRange<unsigned>(0, num_contexts - 1);
    if (src_idx != dst_idx) {
      size_t offset = fdp.ConsumeIntegralInRange<size_t>(0, digest_size - 1);
      size_t max_avail = digest_size - offset; // >= 1
      size_t feed_len = fdp.ConsumeIntegralInRange<size_t>(1, max_avail);
      update_fn(&contexts[dst_idx], feed_len, digests[src_idx].data() + offset);
      finish_fn(&contexts[dst_idx], digests[dst_idx].data());
    }
  }

  // Deinitialise all contexts after this iteration
  for (unsigned i = 0; i < num_contexts; i++) {
    deinit_fn(&contexts[i]);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  for (unsigned i = 0; i < fdp.ConsumeIntegralInRange<unsigned>(1, 4); i++) {
    if (fdp.ConsumeBool()) {
      fuzz_hash_ext_multi<struct mhd_Md5CtxExt>(
        fdp, 64,
        mhd_MD5_init_one_time, mhd_MD5_update, mhd_MD5_finish_reset, mhd_MD5_deinit,
        mhd_MD5_DIGEST_SIZE);
    } else {
      fuzz_hash_ext_multi<struct mhd_Sha256CtxExt>(
        fdp, 64,
        mhd_SHA256_init_one_time, mhd_SHA256_update, mhd_SHA256_finish_reset, mhd_SHA256_deinit,
        mhd_SHA256_DIGEST_SIZE);
    }
  }
  return 0;
}
