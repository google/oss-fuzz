#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <random>

#include "libyuv.h"

#define align_buffer_page_end(var, size)                                \
  uint8_t* var##_mem =                                                  \
      reinterpret_cast<uint8_t*>(malloc(((size) + 4095 + 63) & ~4095)); \
  uint8_t* var = reinterpret_cast<uint8_t*>(                            \
      (intptr_t)(var##_mem + (((size) + 4095 + 63) & ~4095) - (size)) & ~63)

#define free_aligned_buffer_page_end(var) \
  free(var##_mem);                        \
  var = 0

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider provider(data, size);
  // Limit width and height for performance.
  int src_width = provider.ConsumeIntegralInRange<int>(1, 256);
  int src_height = provider.ConsumeIntegralInRange<int>(1, 256);
  int dst_width = provider.ConsumeIntegralInRange<int>(1, 256);
  int dst_height = provider.ConsumeIntegralInRange<int>(1, 256);

  int filter_num =
     provider.ConsumeIntegralInRange<int>(0, libyuv::RotationMode::kRotate270);

  if( size <= 1){
    return 0;
  }

  // i420
  size_t src_i420_y_size = src_width * std::abs(src_height);
  size_t src_i420_uv_size = ((src_width + 1) / 2) * ((std::abs(src_height) + 1) / 2);
  size_t src_i420_size = src_i420_y_size + src_i420_uv_size * 2;
  // i444
  size_t src_i444_y_size = src_width * std::abs(src_height);
  size_t src_i444_uv_size = src_width * std::abs(src_height);
  size_t src_i444_size = src_i444_y_size + src_i444_uv_size * 2;
  // nv12
  size_t src_nv12_y_size = src_width * std::abs(src_height);
  size_t src_nv12_uv_size = ((src_width + 1) / 2) * ((std::abs(src_height) + 1) / 2) * 2;
  size_t src_nv12_size = src_nv12_y_size + src_nv12_uv_size;
  
  //align buffer as needed. copied from rotate unit_test
  align_buffer_page_end(src_i420, src_i420_size); 
  align_buffer_page_end(src_i444, src_i444_size);
  align_buffer_page_end(src_nv12, src_nv12_size);

  //if we don't have enough data to fill buffer just return
  // TODO better way to do this? feels gross
  if(provider.remaining_bytes() < src_i420_size){
    free_aligned_buffer_page_end(src_i420);
    return 0;
  }
  if(provider.remaining_bytes() < src_i444_size){
    free_aligned_buffer_page_end(src_i444);
    return 0;
  }
    if(provider.remaining_bytes() < src_nv12_size){
    free_aligned_buffer_page_end(src_nv12);
    return 0;
  }

  //copy fuzz data to src buffer 
  provider.ConsumeData(src_i420, src_i420_size);
  provider.ConsumeData(src_i444, src_i444_size);
  provider.ConsumeData(src_nv12, src_nv12_size);

  // dst calc and align i420
  size_t dst_i420_y_size = dst_width * dst_height;
  size_t dst_i420_uv_size = ((dst_width + 1) / 2) * ((dst_height + 1) / 2);
  size_t dst_i420_size = dst_i420_y_size + dst_i420_uv_size * 2;
  align_buffer_page_end(dst_i420_c, dst_i420_size);
  align_buffer_page_end(dst_i420_opt, dst_i420_size);

  //dst calc and align i444
  size_t dst_i444_y_size = dst_width * dst_height;
  size_t dst_i444_uv_size = dst_width * dst_height;
  size_t dst_i444_size = dst_i444_y_size + dst_i444_uv_size * 2;
  align_buffer_page_end(dst_i444_c, dst_i444_size);
  align_buffer_page_end(dst_i444_opt, dst_i444_size);

  // dst calc and align nv12
  size_t dst_nv12_y_size = dst_width * dst_height;
  size_t dst_nv12_uv_size = ((dst_width + 1) / 2) * ((dst_height + 1) / 2);
  size_t dst_nv12_size = dst_nv12_y_size + dst_nv12_uv_size * 2;
  align_buffer_page_end(dst_nv12_c, dst_nv12_size);
  align_buffer_page_end(dst_nv12_opt, dst_nv12_size);

  I420Rotate(
        src_i420, src_width, src_i420 + src_i420_y_size, (src_width + 1) / 2,
        src_i420 + src_i420_y_size + src_i420_uv_size, (src_width + 1) / 2,
        dst_i420_opt, dst_width, dst_i420_opt + dst_i420_y_size,
        (dst_width + 1) / 2, dst_i420_opt + dst_i420_y_size + dst_i420_uv_size,
        (dst_width + 1) / 2, src_width, src_height, static_cast<libyuv::RotationMode>(filter_num));
  I444Rotate(src_i444, src_width, src_i444 + src_i444_y_size, src_width,
               src_i444 + src_i444_y_size + src_i444_uv_size, src_width,
               dst_i444_opt, dst_width, dst_i444_opt + dst_i444_y_size,
               dst_width, dst_i444_opt + dst_i444_y_size + dst_i444_uv_size,
               dst_width, src_width, src_height, static_cast<libyuv::RotationMode>(filter_num));
  NV12ToI420Rotate(src_nv12, src_width, src_nv12 + src_nv12_y_size,
                   (src_width + 1) & ~1, dst_nv12_c, dst_width,
                   dst_nv12_c + dst_nv12_y_size, (dst_width + 1) / 2,
                   dst_nv12_c + dst_nv12_y_size + dst_nv12_uv_size,
                   (dst_width + 1) / 2, src_width, src_height,  static_cast<libyuv::RotationMode>(filter_num));

  free_aligned_buffer_page_end(dst_i420_c);
  free_aligned_buffer_page_end(dst_i420_opt);
  free_aligned_buffer_page_end(src_i420);
 
  free_aligned_buffer_page_end(dst_i444_c);
  free_aligned_buffer_page_end(dst_i444_opt);
  free_aligned_buffer_page_end(src_i444);

  free_aligned_buffer_page_end(dst_nv12_c);
  free_aligned_buffer_page_end(dst_nv12_opt);
  free_aligned_buffer_page_end(src_nv12);

  return 0;
}

