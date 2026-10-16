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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size <= 10)
    {
        return 0;
    }

    FuzzedDataProvider fuzzed_data(data, size);
    bool sign = fuzzed_data.ConsumeBool();
    int random_num = fuzzed_data.ConsumeIntegralInRange(0, INT_MAX);

    int part_size = abs(static_cast<int>(size - 10) / 6);
    int width = fuzzed_data.ConsumeIntegralInRange(0, part_size);
    int height = fuzzed_data.ConsumeIntegralInRange(0, part_size / (width ? width : 1));
    int src_subsamp_x = fuzzed_data.ConsumeIntegralInRange(1, 2);
    int src_subsamp_y = fuzzed_data.ConsumeIntegralInRange(1, 2);
    int dst_subsamp_x = fuzzed_data.ConsumeIntegralInRange(1, 2);
    int dst_subsamp_y = fuzzed_data.ConsumeIntegralInRange(1, 2);
    int src_bpc = fuzzed_data.ConsumeIntegralInRange(1, 2);
    int dst_bpc = fuzzed_data.ConsumeIntegralInRange(1, 2);

    const int src_half_width = SUBSAMPLE(width, src_subsamp_x);
    const int src_half_height= SUBSAMPLE(height, src_subsamp_y);
    const int dst_half_width= SUBSAMPLE(width, dst_subsamp_x);
    const int dst_half_height= SUBSAMPLE(height, dst_subsamp_y);

    int src_pixels = width * height * src_bpc;
    int src_half_pixels = src_half_height * src_half_width * src_bpc;
    int dst_pixels = width * height * dst_bpc;

    std::vector<uint8_t> first_part = fuzzed_data.ConsumeBytes<uint8_t>(src_pixels);
    std::vector<uint8_t> second_part = fuzzed_data.ConsumeBytes<uint8_t>(src_half_pixels);
    std::vector<uint8_t> third_part = fuzzed_data.ConsumeBytes<uint8_t>(src_half_pixels);
    uint8_t *src_y = first_part.data();
    uint8_t *src_u = second_part.data();
    uint8_t *src_v = third_part.data();

    height = sign ? height : -height;
    int cpu_flags = generate_cpuflags(random_num);
    int current_cpu_flags =  libyuv::MaskCpuFlags(cpu_flags);

    uint8_t *dst_data = new uint8_t[size];

    uint8_t *dst_y = dst_data;
    uint8_t *dst_uv = dst_data + dst_pixels;
    uint8_t *dst_u = dst_data + dst_pixels;
    uint8_t *dst_v = dst_u + dst_pixels;

    uint16_t *src_y16 = reinterpret_cast<uint16_t *>(src_y);
    uint16_t *src_u16 = reinterpret_cast<uint16_t *>(src_u);
    uint16_t *src_v16 = reinterpret_cast<uint16_t *>(src_v);
    uint16_t *dst_y16 = reinterpret_cast<uint16_t *>(dst_y);
    uint16_t *dst_uv16 = reinterpret_cast<uint16_t *>(dst_uv);
    uint16_t *dst_u16 = reinterpret_cast<uint16_t *>(dst_u); 
    uint16_t *dst_v16 = reinterpret_cast<uint16_t *>(dst_v);

    write_conf(width, height, current_cpu_flags, src_half_width, src_half_height, dst_half_width, dst_half_height);
    

    libyuv::I420ToI420(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I422ToI420(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I444ToI420(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I420ToI422(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I420ToI444(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I420ToI420Mirror(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I422ToI422(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I422ToI444(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I444ToI444(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I010ToI010(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I420ToI010(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I420ToI012(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::H010ToH010(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::H010ToH420(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::H420ToH010(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::H420ToH012(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I010ToI410(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I210ToI410(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I012ToI412(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I212ToI412(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I410ToI010(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I210ToI010(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I412ToI012(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I212ToI012(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_u16, dst_half_width, dst_v16, dst_half_width, width, height);
    libyuv::I010ToI420(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I210ToI420(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I210ToI422(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I410ToI420(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I410ToI444(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I012ToI420(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I212ToI420(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I212ToI422(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I412ToI420(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);
    libyuv::I412ToI444(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y, width, dst_u, dst_half_width, dst_v, dst_half_width, width, height);


    libyuv::I420ToNV12(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_uv, dst_half_width * 2, width, height);
    libyuv::I420ToNV21(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_uv, dst_half_width * 2, width, height);
    libyuv::I422ToNV21(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_uv, dst_half_width * 2, width, height);
    libyuv::I444ToNV12(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_uv, dst_half_width * 2, width, height);
    libyuv::I444ToNV21(src_y, width, src_u, src_half_width, src_v, src_half_width, dst_y, width, dst_uv, dst_half_width * 2, width, height);
    libyuv::I400ToNV21(src_y, width, dst_y, width, dst_uv, dst_half_width * 2, width, height);
    libyuv::I010ToP010(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_uv16, dst_half_width * 2, width, height);
    libyuv::I210ToP210(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_uv16, dst_half_width * 2, width, height);
    libyuv::I012ToP012(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_uv16, dst_half_width * 2, width, height);
    libyuv::I212ToP212(src_y16, width, src_u16, src_half_width, src_v16, src_half_width, dst_y16, width, dst_uv16, dst_half_width * 2, width, height);

    delete[] dst_data;

    return 0;
}