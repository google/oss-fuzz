/*  Copyright 2020 Google Inc.

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

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include <libraw.h>

enum InterpolationOptions {
  Linear = 0,
  Vng = 1, 
  Ppg = 2,
  Ahd = 3,
  Dcb = 4,
  Dht = 11,
  AhdModified = 12
};
static const InterpolationOptions options[] = {Linear, Vng, Ppg, Ahd, Dcb, Dht, AhdModified};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Input less than 15mb
  if (size > 15000000) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);
  LibRaw lib_raw;

  for(int i =0; i < 4; i++)
    lib_raw.output_params_ptr()->aber[i] = fdp.ConsumeFloatingPoint<double>();
  for(int i =0; i < 4; i++)
    lib_raw.output_params_ptr()->user_mul[i] = fdp.ConsumeFloatingPoint<float>();
  for(int i =0; i < 2; i++)
    lib_raw.output_params_ptr()->gamm[i] = fdp.ConsumeFloatingPoint<double>();
  lib_raw.output_params_ptr()->bright = fdp.ConsumeFloatingPoint<float>();
  lib_raw.output_params_ptr()->threshold = fdp.ConsumeFloatingPoint<float>();
  lib_raw.output_params_ptr()->use_auto_wb = fdp.ConsumeIntegral<int>();
  lib_raw.output_params_ptr()->output_color = fdp.ConsumeIntegralInRange<int>(0, 6);
  lib_raw.output_params_ptr()->user_flip = fdp.ConsumeIntegralInRange<int>(0, 7);
  lib_raw.output_params_ptr()->user_black = fdp.ConsumeIntegral<int>();
  lib_raw.output_params_ptr()->user_sat = fdp.ConsumeIntegral<int>();
  lib_raw.output_params_ptr()->auto_bright_thr = fdp.ConsumeFloatingPoint<float>();
  lib_raw.output_params_ptr()->adjust_maximum_thr = fdp.ConsumeFloatingPointInRange<float>(0.f, 1.f);
  lib_raw.output_params_ptr()->fbdd_noiserd = fdp.ConsumeIntegralInRange<int>(0, 5);

  std::vector<char> payload = fdp.ConsumeRemainingBytes<char>();
  int result = lib_raw.open_buffer(payload.data(), payload.size());
  if (result != LIBRAW_SUCCESS) {
    return 0;
  }

  result = lib_raw.unpack();
  if (result != LIBRAW_SUCCESS) {
    return 0;
  }

  result = lib_raw.unpack_thumb();
  if (result != LIBRAW_SUCCESS) {
    return 0;
  }

  result = lib_raw.raw2image();
  if (result != LIBRAW_SUCCESS) {
    return 0;
  }
  lib_raw.free_image();

  for (int i = 0; i < sizeof(options)/sizeof(*options); i++) {
    lib_raw.output_params_ptr()->user_qual = static_cast<int>(options[i]);

    result = lib_raw.dcraw_process();
    if (result != LIBRAW_SUCCESS) {
      return 0;
    }
  }

  return 0;
}
