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

#include <fstream>
#include <iostream>

#include "fuzz_common.h"
#include "libyuv.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace libyuv;

void write_conf(int width, int height, int cpu_flags, int src_stride_y, int src_stride_uv, int dst_y_stride, int dst_uv_stride)
{
        std::cout<< "width = " << std::dec << width << " height= " << std::showpos << height << " cpu_flag = " << std::hex<< std::noshowpos << cpu_flags << " src_stride_y = " << std::dec << src_stride_y << " stride_uv = " << std::dec << src_stride_uv << " dst_y_stride = " << std::dec << dst_y_stride << " dst_uv_stride = " << std::dec << dst_uv_stride << std::endl;

}

int generate_cpuflags(int random_num)
{
    int cpu_info = 0;
    if (random_num & 0x01)
    {
        // disable all cpu specific optimizations.
        cpu_info = 1;
        return cpu_info;
    }

    // enable all cpu specific optimizations.
    cpu_info = -1;

#if defined(__arm__) || defined(__aarch64__)
    random_num &= (kCpuHasNEON);
    return cpu_info &= (~random_num);
#endif

#if !defined(__pnacl__) && !defined(__CLR_VER) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
    random_num &= (kCpuHasX86 | kCpuHasSSE2 | kCpuHasSSSE3 | kCpuHasSSE41 | kCpuHasSSE42 | kCpuHasAVX | kCpuHasAVX2 | kCpuHasERMS | kCpuHasFMA3 | kCpuHasF16C | kCpuHasAVX512BW | kCpuHasAVX512VL | kCpuHasAVX512VNNI | kCpuHasAVX512VBMI | kCpuHasAVX512VBMI2 | kCpuHasAVX512VBITALG | kCpuHasAVX512VPOPCNTDQ | kCpuHasAVXVNNI | kCpuHasAVXVNNIINT8);
    return cpu_info &= ~(random_num);
#endif

#if defined(__mips__) || defined(__linux__)
    random_num &= (kCpuHasMSA);
    return cpu_info &= ~(random_num);
#endif

#if defined(__loongarch__) || defined(__linux__)
    random_num &= (kCpuHasLSX | kCpuHasLASX);
    return cpu_info &= ~(random_num);
#endif

#if defined(__riscv) && defined(__linux__)
    random_num &= (kCpuHasRVV | kCpuHasRVVZVFH);
    return cpu_info &= ~(random_num);

#endif
    return cpu_info;
}