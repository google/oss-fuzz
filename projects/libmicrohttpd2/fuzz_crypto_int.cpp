#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <algorithm>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
  #include "md5_int.h"
  #include "sha256_int.h"
  #include "sha512_256_int.h"
}

// Template functions for processing the hash
template <typename HashType> using InitFn   = void (*)(HashType*);
template <typename HashType> using UpdateFn = void (*)(HashType*, size_t, const uint8_t*);
template <typename HashType> using FinishFn = void (*)(HashType*, uint8_t*);

// General flow for hashing of different type
template <typename HashType>
static void fuzz_hash_int_multi(FuzzedDataProvider &fdp,
                                size_t block_size,
                                InitFn<HashType> init_fn,
                                UpdateFn<HashType> update_fn,
                                FinishFn<HashType> finish_fn,
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
    init_fn(&context[i]);
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
          init_fn(&context[choice]);
        }
        continue;
      }
    }
    if (want == 0 || want > remain) {
      continue;
    }

    // Random re-initialisation between update
    if (fdp.ConsumeBool()) {
      init_fn(&context[choice]);
    }

    update_fn(&context[choice], want, ptr);
    ptr += want;
    remain -= want;

    // Random runcate and reinitialisation between update
    if (fdp.ConsumeBool()) {
      finish_fn(&context[choice], digest[choice].data());
      init_fn(&context[choice]);
    }
  }

  // Fuzz finish function
  for (unsigned i = 0; i < round; i++) {
    finish_fn(&context[i], digest[i].data());
  }

  // Fuzz special case of chaining multiple context
  if (round >= 2 && digest_size && fdp.ConsumeBool()) {
    unsigned src = fdp.ConsumeIntegralInRange<unsigned>(0, round - 1);
    unsigned dst = fdp.ConsumeIntegralInRange<unsigned>(0, round - 1);
    if (src != dst) {
      init_fn(&context[dst]);
      size_t off = fdp.ConsumeIntegralInRange<size_t>(0, digest_size - 1);
      size_t len = std::min(digest_size - off,
                            (size_t)fdp.ConsumeIntegralInRange<size_t>(1, digest_size));
      update_fn(&context[dst], len, digest[src].data() + off);
      finish_fn(&context[dst], digest[dst].data());
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  for (int i = 0; i < fdp.ConsumeIntegralInRange<unsigned>(1, 4); i++) {
    switch (fdp.ConsumeIntegralInRange<int>(0, 2)) {
      case 0:
        fuzz_hash_int_multi<struct mhd_Md5CtxInt>(
          fdp, mhd_MD5_BLOCK_SIZE,
          mhd_MD5_init, mhd_MD5_update, mhd_MD5_finish, mhd_MD5_DIGEST_SIZE);
        break;
      case 1:
        fuzz_hash_int_multi<struct mhd_Sha256CtxInt>(
          fdp, mhd_SHA256_BLOCK_SIZE,
          mhd_SHA256_init, mhd_SHA256_update, mhd_SHA256_finish, mhd_SHA256_DIGEST_SIZE);
        break;
      case 2:
      default:
        fuzz_hash_int_multi<struct mhd_Sha512_256CtxInt>(
          fdp, mhd_SHA512_256_BLOCK_SIZE,
          mhd_SHA512_256_init, mhd_SHA512_256_update, mhd_SHA512_256_finish, mhd_SHA512_256_DIGEST_SIZE);
        break;
    }
  }
  return 0;
}
