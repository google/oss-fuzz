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
  avifROData raw;
  raw.data = Data;
  raw.size = Size;

  avifDecoder *decoder = avifDecoderCreate();
  // avifDecoderSetSource(decoder, AVIF_DECODER_SOURCE_PRIMARY_ITEM);
  avifResult result = avifDecoderParse(decoder, &raw);
  if (result == AVIF_RESULT_OK) {
    // printf("AVIF container reports dimensions: %ux%u (@ %u bpc)\n",
    //        decoder->containerWidth, decoder->containerHeight,
    //        decoder->containerDepth);
    for (int loop = 0; loop < 2; ++loop) {
      // printf("Image decoded: %s\n", inputFilename);
      // printf(" * %2.2f seconds, %d images\n", decoder->duration,
      //        decoder->imageCount);
      int frameIndex = 0;
      while (avifDecoderNextImage(decoder) == AVIF_RESULT_OK) {
        // printf("  * Decoded frame [%d] [pts %2.2f] [duration %2.2f] "
        //        "[keyframe:%s nearest:%u]: %dx%d\n",
        //        frameIndex, decoder->imageTiming.pts,
        //        decoder->imageTiming.duration,
        //        avifDecoderIsKeyframe(decoder, frameIndex) ? "true" : "false",
        //        avifDecoderNearestKeyframe(decoder, frameIndex),
        //        decoder->image->width, decoder->image->height);
        ++frameIndex;
      }

      if (loop != 1) {
        result = avifDecoderReset(decoder);
        if (result == AVIF_RESULT_OK) {
          // printf("Decoder reset! Decoding one more time.\n");
        } else {
          // printf("ERROR: Failed to reset decode: %s\n",
          //        avifResultToString(result));
          break;
        }
      }
    }
  } else {
    // printf("ERROR: Failed to decode image: %s\n",
    // avifResultToString(result));
  }

  avifDecoderDestroy(decoder);
  return 0; // Non-zero return values are reserved for future use.
}
