// OSS-Fuzz target: tflite-micro signal/src/filter_bank_spectral_subtraction.cc
// Tests FilterbankSpectralSubtraction for OOB when num_channels > buffer elems
#include <cstdint>
#include <cstddef>
#include <vector>
#include "signal/src/filter_bank_spectral_subtraction.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size_in) {
  if (size_in < 4) return 0;
  int buf = (static_cast<int>(data[0]) | (static_cast<int>(data[1]) << 8)) % 128 + 1;
  int num_channels = (static_cast<int>(data[2]) | (static_cast<int>(data[3]) << 8)) % 512 + 1;
  tflite::tflm_signal::SpectralSubtractionConfig config;
  config.num_channels = num_channels;
  config.smoothing = 1;
  config.one_minus_smoothing = 1;
  config.min_signal_remaining = 1;
  config.alternate_smoothing = 1;
  config.alternate_one_minus_smoothing = 1;
  config.smoothing_bits = 0;
  config.spectral_subtraction_bits = 8;
  config.clamping = false;
  std::vector<uint32_t> input(buf, 1), output(buf), noise(buf, 1);
  tflite::tflm_signal::FilterbankSpectralSubtraction(
      &config, input.data(), output.data(), noise.data());
  return 0;
}
