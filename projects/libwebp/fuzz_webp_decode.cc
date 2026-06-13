// Copyright 2026 Google LLC
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

// Fuzz harness for the libwebp decoder.
//
// Exercises the main decode path used by browsers, image viewers, and any
// application that calls WebPDecode() on untrusted .webp files:
//
//   WebPGetInfo()           – parses the RIFF/VP8/VP8L/VP8X container header
//   WebPGetFeatures()       – reads width, height, alpha, animation flags
//   WebPDecodeRGB()         – full lossy/lossless decode to RGB
//   WebPDecodeRGBA()        – decode with alpha channel
//   WebPDecodeYUV()         – decode to planar YUV
//
// The harness also exercises the incremental decoder (WebPIDecoder) to reach
// partial-decode code paths that are not hit by the one-shot API.

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "src/webp/decode.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // --- One-shot decode ---
  int width, height;
  if (WebPGetInfo(data, size, &width, &height)) {
    // Sanity-check dimensions to avoid very large allocations.
    if (width > 0 && height > 0 && width <= 16384 && height <= 16384) {
      // Decode to RGBA.
      uint8_t *rgba = WebPDecodeRGBA(data, size, &width, &height);
      WebPFree(rgba);

      // Decode to RGB.
      uint8_t *rgb = WebPDecodeRGB(data, size, &width, &height);
      WebPFree(rgb);

      // Decode to YUV.
      uint8_t *u_plane = nullptr, *v_plane = nullptr;
      int y_stride, uv_stride;
      uint8_t *yuv = WebPDecodeYUV(data, size, &width, &height,
                                   &u_plane, &v_plane,
                                   &y_stride, &uv_stride);
      WebPFree(yuv);
    }
  }

  // --- Feature extraction (parses the bitstream header) ---
  WebPBitstreamFeatures features;
  WebPGetFeatures(data, size, &features);

  // --- Incremental decode ---
  WebPIDecoder *idec = WebPINewDecoder(nullptr);
  if (idec) {
    WebPIAppend(idec, data, size);
    WebPIDelete(idec);
  }

  return 0;
}
