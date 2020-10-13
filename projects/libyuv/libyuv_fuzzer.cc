/* # Copyright 2020 Google Inc. */
/* # */
/* # Licensed under the Apache License, Version 2.0 (the "License"); */
/* # you may not use this file except in compliance with the License. */
/* # You may obtain a copy of the License at */
/* # */
/* #      http://www.apache.org/licenses/LICENSE-2.0 */
/* # */
/* # Unless required by applicable law or agreed to in writing, software */
/* # distributed under the License is distributed on an "AS IS" BASIS, */
/* # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/* # See the License for the specific language governing permissions and */
/* # limitations under the License. */
/* # */
/* ################################################################################ */

#include <climits>
#include <iostream>
#include <vector>

#include "fuzz_common.h"
#include "libyuv.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace std;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) {
        libyuv::I420ToNV21(data, 0, data, 0, data, 0, nullptr, 0, nullptr, 0, 0, 0);
        return 0;
    }

    FuzzedDataProvider fuzzed_data(data, size);

    int range_size = (static_cast<int>(size) + 1) / 3;
    int width = 0, height = 0, kPixels = 0, kHalfPixels = 0;

    width = fuzzed_data.ConsumeIntegralInRange(0, range_size);
    height = fuzzed_data.ConsumeIntegralInRange(0, range_size / (width + 1));
    kPixels = width * height;
    kHalfPixels = ((width + 1) / 2) * ((height + 1) / 2);
    std::vector<uint8_t> first_part = fuzzed_data.ConsumeBytes<uint8_t>(kPixels);
    std::vector<uint8_t> second_part = fuzzed_data.ConsumeBytes<uint8_t>(kHalfPixels);
    std::vector<uint8_t> third_part = fuzzed_data.ConsumeBytes<uint8_t>(kHalfPixels);

    const uint8_t* src_y = first_part.data();
    const uint8_t* src_u = second_part.data();
    const uint8_t* src_v = third_part.data();

    height = fuzzed_data.ConsumeBool() ? height : -height;

    int random_num = fuzzed_data.ConsumeIntegralInRange(0, INT_MAX);
    int cpu_flags = generate_cpuflags(random_num);
    libyuv::MaskCpuFlags(cpu_flags);

    uint8_t* dst_data = new uint8_t[size];

    uint8_t* dst_y = dst_data;
    uint8_t* dst_uv = dst_data + kPixels;

    int src_stride_y = width;
    int src_stride_uv = (width + 1) / 2;

    int dst_stride = fuzzed_data.ConsumeIntegralInRange(0, width);

    int dst_stride_y = dst_stride;
    int dst_stride_uv = ((dst_stride + 1) / 2) * 2;

    write_conf(width, height, cpu_flags, src_stride_y, src_stride_uv, dst_stride_y, dst_stride_uv);

    libyuv::I420ToNV21(src_y, src_stride_y, src_u, src_stride_uv, src_v, src_stride_uv, dst_y, dst_stride_y, dst_uv, dst_stride_uv, width, height);

    delete[] dst_data;

    return 0;
}
