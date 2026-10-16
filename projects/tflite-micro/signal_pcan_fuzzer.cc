// OSS-Fuzz target: tflite-micro signal/src/pcan_argc_fixed.cc
// Tests ApplyPcanAutoGainControlFixed for OOB when num_channels > buffer elems
#include <cstdint>
#include <cstddef>
#include <vector>
#include "signal/src/pcan_argc_fixed.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size_in) {
  if (size_in < 4) return 0;
  int buf = (static_cast<int>(data[0]) | (static_cast<int>(data[1]) << 8)) % 128 + 1;
  int num_channels = (static_cast<int>(data[2]) | (static_cast<int>(data[3]) << 8)) % 512 + 1;
  std::vector<int16_t> gain_lut(2048, 0);
  std::vector<uint32_t> noise(buf, 1), output(buf, 1);
  tflite::tflm_signal::ApplyPcanAutoGainControlFixed(
      gain_lut.data(), 6, noise.data(), output.data(), num_channels);
  return 0;
}
