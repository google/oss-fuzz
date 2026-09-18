// OSS-Fuzz target: tflite-micro signal/src/overlap_add.cc
// Tests tflm_signal::OverlapAdd for OOB when output_size > input_size
// (missing frame_step <= frame_size validation in OverlapAddPrepare)
#include <cstdint>
#include <cstddef>
#include <vector>
#include "signal/src/overlap_add.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4) return 0;
  int input_size = (static_cast<int>(data[0]) | (static_cast<int>(data[1]) << 8)) % 256 + 1;
  int output_size = (static_cast<int>(data[2]) | (static_cast<int>(data[3]) << 8)) % 512 + 1;
  std::vector<int16_t> buffer(input_size), input(input_size), output(output_size);
  for (int i = 0; i < input_size; ++i) { input[i] = static_cast<int16_t>(i); buffer[i] = 1; }
  tflm_signal::OverlapAdd(input.data(), buffer.data(), input_size,
                          output.data(), output_size);
  return 0;
}
