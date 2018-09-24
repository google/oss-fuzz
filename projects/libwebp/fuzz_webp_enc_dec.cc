// Copyright 2018 Google Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include "webp/encode.h"
#include "webp/decode.h"
#include "img_alpha.h"
#include "img_grid.h"
#include "img_peak.h"
#include "dsp/dsp.h"

namespace {

const VP8CPUInfo LibGetCPUInfo = VP8GetCPUInfo;

int GetCPUInfoNoSSE41(CPUFeature feature) {
  if (feature == kSSE4_1 || feature == kAVX) return 0;
  return LibGetCPUInfo(feature);
}

int GetCPUInfoNoAVX(CPUFeature feature) {
  if (feature == kAVX) return 0;
  return LibGetCPUInfo(feature);
}

int GetCPUInfoForceSlowSSSE3(CPUFeature feature) {
  if (feature == kSlowSSSE3 && LibGetCPUInfo(kSSE3)) {
    return 1;  // we have SSE3 -> force SlowSSSE3
  }
  return LibGetCPUInfo(feature);
}

int GetCPUInfoOnlyC(CPUFeature feature) {
  return false;
}

const VP8CPUInfo kVP8CPUInfos[5] = {
    GetCPUInfoOnlyC, GetCPUInfoForceSlowSSSE3,
    GetCPUInfoNoSSE41, GetCPUInfoNoAVX, LibGetCPUInfo
};

static uint32_t Extract(uint32_t max, const uint8_t data[], size_t size,
                        uint32_t* const bit_pos) {
  uint32_t v = 0;
  int range = 1;
  while (*bit_pos < 8 * size && range <= max) {
    const uint8_t mask = 1u << (*bit_pos & 7);
    v = (v << 1) | !!(data[*bit_pos >> 3] & mask);
    range <<= 1;
    ++*bit_pos;
  }
  return v % (max + 1);
}

static int max(int a, int b) { return ((a < b) ? b : a); }

}  //  namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* const data, size_t size) {
  // Extract a configuration from the packed bits.
  WebPConfig config;
  if (!WebPConfigInit(&config)) {
    fprintf(stderr, "WebPConfigInit failed.\n");
    abort();
  }
  uint32_t bit_pos = 0;
  config.lossless = Extract(1, data, size, &bit_pos);
  config.quality = Extract(100, data, size, &bit_pos);
  config.method = Extract(6, data, size, &bit_pos);
  config.image_hint =
      (WebPImageHint)Extract(WEBP_HINT_LAST - 1, data, size, &bit_pos);
  config.segments = 1 + Extract(3, data, size, &bit_pos);
  config.sns_strength = Extract(100, data, size, &bit_pos);
  config.filter_strength = Extract(100, data, size, &bit_pos);
  config.filter_sharpness = Extract(7, data, size, &bit_pos);
  config.filter_type = Extract(1, data, size, &bit_pos);
  config.autofilter = Extract(1, data, size, &bit_pos);
  config.alpha_compression = Extract(1, data, size, &bit_pos);
  config.alpha_filtering = Extract(2, data, size, &bit_pos);
  config.alpha_quality = Extract(100, data, size, &bit_pos);
  config.pass = 1 + Extract(9, data, size, &bit_pos);
  config.show_compressed = 1;
  config.preprocessing = Extract(2, data, size, &bit_pos);
  config.partitions = Extract(3, data, size, &bit_pos);
  config.partition_limit = 10 * Extract(10, data, size, &bit_pos);
  config.emulate_jpeg_size = Extract(1, data, size, &bit_pos);
  config.thread_level = Extract(1, data, size, &bit_pos);
  config.low_memory = Extract(1, data, size, &bit_pos);
  config.near_lossless = 20 * Extract(5, data, size, &bit_pos);
  config.exact = Extract(1, data, size, &bit_pos);
  config.use_delta_palette = Extract(1, data, size, &bit_pos);
  config.use_sharp_yuv = Extract(1, data, size, &bit_pos);
  if (!WebPValidateConfig(&config)) {
    fprintf(stderr, "WebPValidateConfig failed.\n");
    abort();
  }

  // Init the source picture.
  WebPPicture pic;
  if (!WebPPictureInit(&pic)) {
    fprintf(stderr, "WebPPictureInit failed.\n");
    abort();
  }
  pic.use_argb = Extract(1, data, size, &bit_pos);

  VP8GetCPUInfo = kVP8CPUInfos[Extract(4, data, size, &bit_pos)];

  // Pick a source picture.
  const uint8_t* kImagesData[] = {
      kImgAlphaData,
      kImgGridData,
      kImgPeakData
  };
  const int kImagesWidth[] = {
      kImgAlphaWidth,
      kImgGridWidth,
      kImgPeakWidth
  };
  const int kImagesHeight[] = {
      kImgAlphaHeight,
      kImgGridHeight,
      kImgPeakHeight
  };
  const size_t kNbImages = sizeof(kImagesData) / sizeof(kImagesData[0]);
  const size_t image_index = Extract(kNbImages - 1, data, size, &bit_pos);
  const uint8_t* const image_data = kImagesData[image_index];
  pic.width = kImagesWidth[image_index];
  pic.height = kImagesHeight[image_index];
  pic.argb_stride = pic.width * 4 * sizeof(uint8_t);

  // Read the bytes.
  if (!WebPPictureImportRGBA(&pic, image_data, pic.argb_stride)) {
    fprintf(stderr, "Can't read input image: %zu\n", image_index);
    WebPPictureFree(&pic);
    abort();
  }

  // Crop and scale.
  const bool alter_input = Extract(1, data, size, &bit_pos) != 0;
  const bool crop_or_scale = Extract(1, data, size, &bit_pos) != 0;
  const int width_ratio = 1 + Extract(7, data, size, &bit_pos);
  const int height_ratio = 1 + Extract(7, data, size, &bit_pos);
  if (alter_input) {
    if (crop_or_scale) {
      const uint32_t left_ratio = 1 + Extract(7, data, size, &bit_pos);
      const uint32_t top_ratio = 1 + Extract(7, data, size, &bit_pos);
      const int cropped_width = max(1, pic.width / width_ratio);
      const int cropped_height = max(1, pic.height / height_ratio);
      const int cropped_left = (pic.width - cropped_width) / left_ratio;
      const int cropped_top = (pic.height - cropped_height) / top_ratio;
      if (!WebPPictureCrop(&pic, cropped_left, cropped_top, cropped_width,
                           cropped_height)) {
        fprintf(stderr, "WebPPictureCrop failed. Parameters: %d,%d,%d,%d\n",
                cropped_left, cropped_top, cropped_width, cropped_height);
        WebPPictureFree(&pic);
        abort();
      }
    } else {
      const int scaled_width = 1 + pic.width * width_ratio / 4;
      const int scaled_height = 1 + pic.height * height_ratio / 4;
      if (!WebPPictureRescale(&pic, scaled_width, scaled_height)) {
        fprintf(stderr, "WebPPictureRescale failed. Parameters: %d,%d\n",
                scaled_width, scaled_height);
        WebPPictureFree(&pic);
        abort();
      }
    }
  }

  // Skip the cruncher except on small images, it's likely to timeout.
  if (config.lossless && config.quality == 100. && config.method == 6 &&
      pic.width * pic.height >= 16 * 16) {
    config.lossless = 0;
  }
  if (config.alpha_quality == 100 && config.method == 6 &&
      pic.width * pic.height >= 16 * 16) {
    config.alpha_quality = 99;
  }

  // Encode.
  WebPMemoryWriter memory_writer;
  WebPMemoryWriterInit(&memory_writer);
  pic.writer = WebPMemoryWrite;
  pic.custom_ptr = &memory_writer;
  if (!WebPEncode(&config, &pic)) {
    fprintf(stderr, "WebPEncode failed. Error code: %d\nFile: %zu\n",
            pic.error_code, image_index);
    WebPMemoryWriterClear(&memory_writer);
    WebPPictureFree(&pic);
    abort();
  }

  // Try decoding the result.
  int w, h;
  const uint8_t* const out_data = memory_writer.mem;
  const size_t out_size = memory_writer.size;
  uint8_t* const rgba = WebPDecodeBGRA(out_data, out_size, &w, &h);
  if (rgba == nullptr || w != pic.width || h != pic.height) {
    fprintf(stderr, "WebPDecodeBGRA failed.\nFile: %zu\n", image_index);
    WebPFree(rgba);
    WebPMemoryWriterClear(&memory_writer);
    WebPPictureFree(&pic);
    abort();
  }

  // Compare the results if exact encoding.
  if (pic.use_argb && config.lossless && config.near_lossless == 100) {
    const uint32_t* src1 = (const uint32_t*)rgba;
    const uint32_t* src2 = pic.argb;
    for (int y = 0; y < h; ++y, src1 += w, src2 += pic.argb_stride) {
      for (int x = 0; x < w; ++x) {
        uint32_t v1 = src1[x], v2 = src2[x];
        if (!config.exact) {
          if ((v1 & 0xff000000u) == 0 || (v2 & 0xff000000u) == 0) {
            // Only keep alpha for comparison of fully transparent area.
            v1 &= 0xff000000u;
            v2 &= 0xff000000u;
          }
        }
        if (v1 != v2) {
          fprintf(stderr,
                  "Lossless compression failed pixel-exactness.\nFile: %zu\n",
                  image_index);
          WebPFree(rgba);
          WebPMemoryWriterClear(&memory_writer);
          WebPPictureFree(&pic);
          abort();
        }
      }
    }
  }

  WebPFree(rgba);
  WebPMemoryWriterClear(&memory_writer);
  WebPPictureFree(&pic);
  return 0;
}
