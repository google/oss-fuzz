// OSS-Fuzz target: tflite-micro signal/micro/kernels/rfft.cc Eval loop
// Tests for OOB when input_length > fft_length (scratch buffer overflow)
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

using T = int16_t;
volatile int64_t g_sink = 0;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4) return 0;
  int fft_length = (static_cast<int>(data[0]) | (static_cast<int>(data[1]) << 8)) % 256 + 1;
  int input_length = (static_cast<int>(data[2]) | (static_cast<int>(data[3]) << 8)) % 512 + 1;
  int input_size = input_length;
  std::vector<T> work_area(fft_length), input_data(input_size);
  for (int i = 0; i < input_size; ++i) input_data[i] = static_cast<T>(i);
  for (int input_idx = 0; input_idx < input_size; input_idx += input_length) {
    memcpy(work_area.data(), &input_data[input_idx], sizeof(T) * input_length);
    memset(&work_area[input_length], 0, sizeof(T) * (fft_length - input_length));
    for (int k = 0; k < fft_length; ++k) g_sink += work_area[k];
  }
  return 0;
}
