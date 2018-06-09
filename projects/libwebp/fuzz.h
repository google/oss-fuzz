#include <stdint.h>
#include <stdlib.h>

// Arbitrary limit to prevent OOM, timeout, or slow execution.
static const size_t fuzz_px_limit = 1024 * 1024;

// Reads and sums (up to) 128 spread-out bytes.
static uint8_t fuzz_hash(const uint8_t* data, size_t size) {
  uint8_t value = 0;
  size_t incr = size / 128;
  if (!incr) incr = 1;
  for (size_t i = 0; i < size; i += incr)
    value += data[i];
  return value;
}
