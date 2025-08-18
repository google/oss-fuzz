#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <algorithm>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include "md5_ext.h"
  #include "sha256_ext.h"
}

// Template functions for processing the hash
template <typename HashType> using InitOnceFn = void (*)(HashType*);
template <typename HashType> using UpdateFn   = void (*)(HashType*, size_t, const uint8_t*);
template <typename HashType> using FinishFn   = void (*)(HashType*, uint8_t*);
template <typename HashType> using DeinitFn   = void (*)(HashType*);

// General flow for hashing of different type
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

  // Prepare random data
  size_t pick_len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  std::vector<uint8_t> raw = fdp.ConsumeBytes<uint8_t>(pick_len);

  // Fuzz random round of hash initialisation
  const unsigned round = fdp.ConsumeIntegralInRange<unsigned>(1, 4);
  std::vector<HashType> context(round);
  std::vector<std::vector<uint8_t>> digest(round, std::vector<uint8_t>(digest_size));
  for (unsigned i = 0; i < round; i++) {
    init_once(&context[i]);
  }

  // Shift the data to introduce possible misalign
  const size_t pad = fdp.ConsumeIntegralInRange<size_t>(0, 64);
  std::vector<uint8_t> storage(pad + raw.size());
  if (!raw.empty()) {
    memcpy(storage.data() + pad, raw.data(), raw.size());
  }
  const uint8_t *ptr = storage.data() + pad;
  size_t remain = raw.size();

  // Fuzz random round of update
  unsigned iters = fdp.ConsumeIntegralInRange<unsigned>(1, 4);

  while (iters-- && remain > 0) {
    // Choose a context
    const unsigned choice = (round == 1) ? 0 : fdp.ConsumeIntegralInRange<unsigned>(0, round - 1);

    // Choose different shift pattern
    enum Pattern { LESS1, EQ, PLUS1, SMALL, RANDOM, TAIL, HALT };
    Pattern pat = fdp.PickValueInArray<Pattern>({LESS1, EQ, PLUS1, SMALL, RANDOM, TAIL, HALT});

    size_t want = 0;
    switch (pat) {
      case LESS1:
        if (block_size > 1) {
          want = std::min(remain, block_size - 1);
        }
        break;
      case EQ:
        want = std::min(remain, block_size);
        break;
      case PLUS1:
        want = std::min(remain, block_size + 1);
        break;
      case SMALL: {
        size_t small = (size_t)fdp.ConsumeIntegralInRange<int>(1, 32);
        want = std::min(remain, small);
        break;
      }
      case RANDOM:
        want = (remain >= 1) ? (size_t)fdp.ConsumeIntegralInRange<size_t>(1, remain) : 0;
        break;
      case TAIL:
        want = remain;
        break;
      case HALT: {
        size_t step  = std::max<size_t>(1, fdp.ConsumeIntegralInRange<size_t>(1, block_size));
        size_t loops = fdp.ConsumeIntegralInRange<size_t>(1, 4);
        for (size_t j = 0; j < loops && remain > 0; j++) {
          size_t w = std::min(remain, step);
          update_fn(&context[choice], w, ptr);
          ptr += w;
          remain -= w;
        }

        // Early finish
        if (fdp.ConsumeBool()) {
          finish_fn(&context[choice], digest[choice].data());
        }
        continue;
      }
    }

    if (want == 0 || want > remain) {
      continue;
    }

    // Random reset between updates
    if (fdp.ConsumeBool()) {
      finish_fn(&context[choice], digest[choice].data());
    }

    update_fn(&context[choice], want, ptr);
    ptr += want;
    remain -= want;

    // Random truncate and reset between update
    if (fdp.ConsumeBool()) {
      finish_fn(&context[choice], digest[choice].data());
    }
  }

  // Fuzz finish_reset function
  for (unsigned i = 0; i < round; i++) {
    finish_fn(&context[i], digest[i].data());
  }

  // Fuzz special case of chaining multiple context
  if (round >= 2 && digest_size && fdp.ConsumeBool()) {
    unsigned src = fdp.ConsumeIntegralInRange<unsigned>(0, round - 1);
    unsigned dst = fdp.ConsumeIntegralInRange<unsigned>(0, round - 1);
    if (src != dst) {
      size_t off = fdp.ConsumeIntegralInRange<size_t>(0, digest_size - 1);
      size_t max_avail = digest_size - off; // >= 1
      size_t len = fdp.ConsumeIntegralInRange<size_t>(1, max_avail);
      update_fn(&context[dst], len, digest[src].data() + off);
      finish_fn(&context[dst], digest[dst].data());
    }
  }

  // Deinitialise all contexts
  for (unsigned i = 0; i < round; i++) {
    deinit_fn(&context[i]);
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
