#define XXH_INLINE_ALL
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "xxhash.h"

// Fuzz the xxHash hashing library.
// Exercises: one-shot and streaming variants of XXH32, XXH64,
// XXH3_64, and XXH3_128, plus the secret-seed streaming APIs.
// These are not parse paths per se but the library is security-
// critical infrastructure and has had integer overflow bugs before.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Derive a seed from the first 8 bytes (or 0 if too short).
    uint64_t seed64 = 0;
    uint32_t seed32 = 0;
    if (size >= 8) {
        memcpy(&seed64, data, 8);
        seed32 = static_cast<uint32_t>(seed64);
    }

    // --- One-shot hashes ---
    (void)XXH32(data, size, seed32);
    (void)XXH64(data, size, seed64);
    (void)XXH3_64bits_withSeed(data, size, seed64);
    (void)XXH128(data, size, seed64);

    // --- XXH32 streaming ---
    {
        XXH32_state_t *state = XXH32_createState();
        if (state) {
            XXH32_reset(state, seed32);
            // Feed in two halves to exercise update path.
            size_t half = size / 2;
            XXH32_update(state, data, half);
            XXH32_update(state, data + half, size - half);
            (void)XXH32_digest(state);
            XXH32_freeState(state);
        }
    }

    // --- XXH64 streaming ---
    {
        XXH64_state_t *state = XXH64_createState();
        if (state) {
            XXH64_reset(state, seed64);
            size_t half = size / 2;
            XXH64_update(state, data, half);
            XXH64_update(state, data + half, size - half);
            (void)XXH64_digest(state);
            XXH64_freeState(state);
        }
    }

    // --- XXH3 streaming (64-bit) ---
    {
        XXH3_state_t *state = XXH3_createState();
        if (state) {
            XXH3_64bits_reset_withSeed(state, seed64);
            size_t third = size / 3;
            XXH3_64bits_update(state, data, third);
            XXH3_64bits_update(state, data + third, size - third);
            (void)XXH3_64bits_digest(state);
            XXH3_freeState(state);
        }
    }

    // --- XXH3 streaming (128-bit) ---
    {
        XXH3_state_t *state = XXH3_createState();
        if (state) {
            XXH3_128bits_reset_withSeed(state, seed64);
            XXH3_128bits_update(state, data, size);
            (void)XXH3_128bits_digest(state);
            XXH3_freeState(state);
        }
    }

    return 0;
}
