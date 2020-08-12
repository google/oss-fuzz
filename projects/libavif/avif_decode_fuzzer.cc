// Copyright 2020 Google Inc.
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
//###############################################################################

#include "avif/avif.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static avifRGBFormat rgbFormats[] = {AVIF_RGB_FORMAT_RGB,
                                       AVIF_RGB_FORMAT_RGBA};
  static size_t rgbFormatsCount = sizeof(rgbFormats) / sizeof(rgbFormats[0]);

  static avifChromaUpsampling upsamplings[] = {AVIF_CHROMA_UPSAMPLING_BILINEAR,
                                               AVIF_CHROMA_UPSAMPLING_NEAREST};
  static size_t upsamplingsCount = sizeof(upsamplings) / sizeof(upsamplings[0]);

  static uint32_t rgbDepths[] = {8, 10};
  static size_t rgbDepthsCount = sizeof(rgbDepths) / sizeof(rgbDepths[0]);

  static uint32_t yuvDepths[] = {8, 10};
  static size_t yuvDepthsCount = sizeof(yuvDepths) / sizeof(yuvDepths[0]);

  avifROData raw;
  raw.data = Data;
  raw.size = Size;

  avifDecoder *decoder = avifDecoderCreate();
  avifResult result = avifDecoderParse(decoder, &raw);
  if (result == AVIF_RESULT_OK) {
    for (int loop = 0; loop < 2; ++loop) {
      while (avifDecoderNextImage(decoder) == AVIF_RESULT_OK) {
        avifRGBImage rgb;
        avifRGBImageSetDefaults(&rgb, decoder->image);

        for (size_t rgbFormatsIndex = 0; rgbFormatsIndex < rgbFormatsCount;
             ++rgbFormatsIndex) {
          for (size_t upsamplingsIndex = 0; upsamplingsIndex < upsamplingsCount;
               ++upsamplingsIndex) {
            for (size_t rgbDepthsIndex = 0; rgbDepthsIndex < rgbDepthsCount;
                 ++rgbDepthsIndex) {
              // Convert to RGB
              rgb.format = rgbFormats[rgbFormatsIndex];
              rgb.depth = rgbDepths[rgbDepthsIndex];
              rgb.chromaUpsampling = upsamplings[upsamplingsIndex];
              avifRGBImageAllocatePixels(&rgb);
              avifResult rgbResult = avifImageYUVToRGB(decoder->image, &rgb);
              if (rgbResult == AVIF_RESULT_OK) {
                for (size_t yuvDepthsIndex = 0; yuvDepthsIndex < yuvDepthsCount;
                     ++yuvDepthsIndex) {
                  // ... and back to YUV
                  avifImage *tempImage = avifImageCreate(
                      decoder->image->width, decoder->image->height,
                      yuvDepths[yuvDepthsIndex], decoder->image->yuvFormat);
                  avifResult yuvResult = avifImageRGBToYUV(tempImage, &rgb);
                  if (yuvResult != AVIF_RESULT_OK) {
                  }
                  avifImageDestroy(tempImage);
                }
              }

              avifRGBImageFreePixels(&rgb);
            }
          }
        }
      }

      if (loop != 1) {
        result = avifDecoderReset(decoder);
        if (result == AVIF_RESULT_OK) {
        } else {
          break;
        }
      }
    }
  }

  avifDecoderDestroy(decoder);
  return 0; // Non-zero return values are reserved for future use.
}
