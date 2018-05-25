#include <stdlib.h>

#include "webp/decode.h"

// Arbitrary limit of 4MB buffer to prevent OOM, timeout, or slow execution.
static const size_t px_limit = 1024 * 1024;

// Reads and sums (up to) 128 spread-out bytes.
static uint8_t hash(const uint8_t* data, size_t size) {
  uint8_t value = 0;
  size_t incr = size / 128;
  if (!incr) incr = 1;
  for (size_t i = 0; i < size; i += incr)
    value += data[i];
  return value;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int w, h;
  if (!WebPGetInfo(data, size, &w, &h))
    return 0;
  if ((size_t)w * h > px_limit)
    return 0;

  const uint8_t value = hash(data, size);
  uint8_t* buf = nullptr;

  // This is verbose, but covers all available variants.
  // For functions that decode into an external buffer, an intentionally
  // too small buffer can be given with low probability.
  if (value < 0x16) {
    buf = WebPDecodeRGBA(data, size, &w, &h);
  } else if (value < 0x2b) {
    buf = WebPDecodeARGB(data, size, &w, &h);
  } else if (value < 0x40) {
    buf = WebPDecodeBGRA(data, size, &w, &h);
  } else if (value < 0x55) {
    buf = WebPDecodeRGB(data, size, &w, &h);
  } else if (value < 0x6a) {
    buf = WebPDecodeBGR(data, size, &w, &h);
  } else if (value < 0x7f) {
    uint8_t *u, *v;
    int stride, uv_stride;
    buf = WebPDecodeYUV(data, size, &w, &h, &u, &v, &stride, &uv_stride);
  } else if (value < 0xe8) {
    int stride = (value < 0xbe ? 4 : 3) * w;
    size_t buf_size = stride * h;
    if (value % 0x10 == 0) buf_size--;
    uint8_t* ext_buf = (uint8_t*)malloc(buf_size);
    if (value < 0x94) {
      WebPDecodeRGBAInto(data, size, ext_buf, buf_size, stride);
    } else if (value < 0xa9) {
      WebPDecodeARGBInto(data, size, ext_buf, buf_size, stride);
    } else if (value < 0xbe) {
      WebPDecodeBGRAInto(data, size, ext_buf, buf_size, stride);
    } else if (value < 0xd3) {
      WebPDecodeRGBInto(data, size, ext_buf, buf_size, stride);
    } else {
      WebPDecodeBGRInto(data, size, ext_buf, buf_size, stride);
    }
    free(ext_buf);
  } else {
    size_t luma_size = w * h;
    int uv_stride = (w + 1) / 2;
    size_t u_size = uv_stride * (h + 1) / 2;
    size_t v_size = uv_stride * (h + 1) / 2;
    if (value % 0x10 == 0) {
      if (size & 1) luma_size--;
      if (size & 2) u_size--;
      if (size & 4) v_size--;
    }
    uint8_t* luma_buf = (uint8_t*)malloc(luma_size);
    uint8_t* u_buf = (uint8_t*)malloc(u_size);
    uint8_t* v_buf = (uint8_t*)malloc(v_size);
    WebPDecodeYUVInto(data, size, luma_buf, luma_size, w /* luma_stride */,
                      u_buf, u_size, uv_stride, v_buf, v_size, uv_stride);
    free(luma_buf);
    free(u_buf);
    free(v_buf);
  }

  if (buf)
    WebPFree(buf);

  return 0;
}
