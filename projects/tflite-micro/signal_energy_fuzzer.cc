// OSS-Fuzz target: tflite-micro signal/src/energy.cc
// Tests SpectrumToEnergy for OOB when end_index > input element count
#include <cstdint>
#include <cstddef>
#include <vector>
#include "signal/src/energy.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size_in) {
  if (size_in < 6) return 0;
  int buf = (static_cast<int>(data[0]) | (static_cast<int>(data[1]) << 8)) % 128 + 1;
  int start = (static_cast<int>(data[2]) | (static_cast<int>(data[3]) << 8)) % 64;
  int end_index = (static_cast<int>(data[4]) | (static_cast<int>(data[5]) << 8)) % 512 + 1;
  if (start >= end_index) start = 0;
  std::vector<Complex<int16_t>> input(buf);
  std::vector<uint32_t> output(buf);
  for (int i = 0; i < buf; ++i) { input[i].real = static_cast<int16_t>(i); input[i].imag = 1; }
  tflite::tflm_signal::SpectrumToEnergy(input.data(), start, end_index, output.data());
  return 0;
}
