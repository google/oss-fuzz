/* Copyright 2023 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <fftw3.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // For reference, fftw_compelx is defined:
  // typedef double fftw_complex[2]
  if (size < 1) {
    return 0;
  }
  uint8_t ARRAY_SIZE = (*data) % 250 + 1;
  data++;
  size -= 1;
  if ((ARRAY_SIZE * sizeof(double) * 2) > size) {
    return 0;
  }
  fftw_complex signal[ARRAY_SIZE];
  fftw_complex result[ARRAY_SIZE];

  // Seed the signals with fuzz data
  memcpy(signal, data, (ARRAY_SIZE * sizeof(double) * 2));

  fftw_plan plan =
      fftw_plan_dft_1d(ARRAY_SIZE, signal, result, FFTW_FORWARD, FFTW_ESTIMATE);

  fftw_execute(plan);
  fftw_destroy_plan(plan);

  return 0;
}
