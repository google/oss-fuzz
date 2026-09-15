// OSS-Fuzz target: tflite-micro signal/src/window.cc
// Tests tflm_signal::ApplyWindow for OOB when size > buffer element count
#include <cstdint>
#include <cstddef>
#include <vector>
#include "signal/src/window.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size_in) {
  if (size_in < 4) return 0;
  int buf = (static_cast<int>(data[0]) | (static_cast<int>(data[1]) << 8)) % 128 + 1;
  int size = (static_cast<int>(data[2]) | (static_cast<int>(data[3]) << 8)) % 512 + 1;
  std::vector<int16_t> input(buf), window(buf), output(buf);
  for (int i = 0; i < buf; ++i) { input[i] = static_cast<int16_t>(i); window[i] = 1; }
  tflm_signal::ApplyWindow(input.data(), window.data(), size, 0, output.data());
  return 0;
}
