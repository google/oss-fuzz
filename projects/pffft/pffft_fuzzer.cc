// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>

#include "pffft.h"

namespace {

constexpr size_t kSizeOfFloat = sizeof(float);

bool IsValidSize(size_t n) {
  if (n == 0) { return false; }
  // PFFFT only supports transforms for inputs of length N of the form
  // N = (2^a)*(3^b)*(5^c) where a >= 5, b >=0, c >= 0.
  constexpr std::array<int, 3> kFactors = {2, 3, 5};
  std::array<int, kFactors.size()> factorization{};
  for (size_t i = 0; i < kFactors.size(); ++i) {
    const int factor = kFactors[i];
    while (n % factor == 0) {
      n /= factor;
      factorization[i]++;
    }
  }
  return factorization[0] >= 5 && n == 1;
}

}  // namespace

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Set the number of FFT points to use |data| as input vector.
  // The latter is truncated if the number of bytes is not an integer
  // multiple of the size of a float.
  const size_t fft_size = size / kSizeOfFloat;
  if (!IsValidSize(fft_size)) {
    return 0;
  }

  const size_t number_of_bytes = fft_size * kSizeOfFloat;
  assert(number_of_bytes <= size);
  float* buf = static_cast<float*>(pffft_aligned_malloc(number_of_bytes));
  std::memcpy(buf, reinterpret_cast<const float*>(data), number_of_bytes);

  PFFFT_Setup* pffft_setup = pffft_new_setup(fft_size, PFFFT_REAL);

  pffft_transform(pffft_setup, buf, buf, NULL, PFFFT_FORWARD);
  pffft_transform(pffft_setup, buf, buf, NULL, PFFFT_BACKWARD);
  
  pffft_aligned_free(buf);
  pffft_destroy_setup(pffft_setup);

  return 0;
}
