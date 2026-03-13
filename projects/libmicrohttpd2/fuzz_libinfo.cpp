// Copyright 2025 Google LLC
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
////////////////////////////////////////////////////////////////////////////////
#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <cstdlib>
#include <algorithm>

#include "microhttpd2.h"
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Generate random ids
  int fixed_id   = fdp.ConsumeIntegral<int>();
  int dynamic_id = fdp.ConsumeIntegral<int>();

  // Generate random raw data
  std::vector<uint8_t> raw_data = fdp.ConsumeRemainingBytes<uint8_t>();

  // Fuzz MHD_lib_get_info_fixed_sz
  MHD_lib_get_info_fixed_sz(
      static_cast<MHD_LibInfoFixed>(fixed_id),
      raw_data.size() > 0 ? reinterpret_cast<MHD_LibInfoFixedData*>(raw_data.data()) : nullptr,
      raw_data.size());

  // Fuzz MHD_lib_get_info_dynamic_sz
  MHD_lib_get_info_dynamic_sz(
      static_cast<MHD_LibInfoDynamic>(dynamic_id),
      raw_data.size() > 0 ? reinterpret_cast<MHD_LibInfoDynamicData*>(raw_data.data()) : nullptr,
      raw_data.size());

  return 0;
}
