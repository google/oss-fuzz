#include <iostream>
#include <cstdlib>
#include <ctime>
#include "libyuv.h"
using namespace std;

unsigned int fastrand_seed;
inline int fastrand()
{
    fastrand_seed = fastrand_seed * 214013u + 2531011u;
    return static_cast<int>((fastrand_seed >> 16) & 0xffff);
}


extern "C" int LLVMFuzzerInitialize(const uint8_t *Data, size_t Size)
{
    srand(time(nullptr));
    fastrand_seed = rand();
    return 0;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

    if (size == 0)
    {
        libyuv::I420ToNV21(data, 0, data, 0, data, 0, nullptr, 0, nullptr, 0, 0, 0);
        return 0;
    }

    int height = 0, width = 0, kPixels = 0, kHalfPixels = 0;
    int range_size = (static_cast<int>(size) + 1) / 2;
    do
    {
        height = fastrand() % range_size ;
        width = fastrand() % range_size;
        kPixels = width * height;
        kHalfPixels = (width + 1) / 2 * (height + 1) / 2;
    }
    while (kPixels + kHalfPixels * 2 > size);

    uint8_t *dst_data = new uint8_t [size];

    uint8_t *dst_y_data = dst_data;
    uint8_t *dst_uv_data = dst_data + kPixels;

    const uint8_t *src_y_data = data;
    const uint8_t *src_u_data = data + kPixels;
    const uint8_t *src_v_data = data + kPixels + kHalfPixels;
    libyuv::I420ToNV21(src_y_data, width, src_u_data, (width + 1) / 2, src_v_data, (width + 1) / 2, dst_y_data, width, dst_uv_data, width, width, height);
    delete [] dst_data;
    return 0;
}
