// Copyright 2020 Google LLC
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

#include <stddef.h>
#include <stdlib.h>

#include "opus.h"
#include "opus_multistream.h"

struct TocInfo {
  opus_int32 frequency;  // in [Hz*1000]
  int channels;          // number of channels; either 1 or 2
  int frame_len_x2;      // in [ms*2]. x2 is to avoid float value of 2.5 ms
};

void extractTocInfo(const uint8_t toc, struct TocInfo *const info) {
  const int frame_lengths_x2[3][4] = {
    {20, 40, 80, 120},
    {20, 40, 20, 40},
    {5, 10, 20, 40}
  };

  info->channels = toc & 4 ? 2 : 1;

  const uint8_t config = toc >> 3;

  int len_index;
  if (config < 12) {
    len_index = 0;
  } else if (config < 16) {
    len_index = 1;
  } else {
    len_index = 2;
  }
  info->frame_len_x2 = frame_lengths_x2[len_index][config & 3];

  switch (config >> 2) {
    case 0: info->frequency = 8; break;
    case 1: info->frequency = 12; break;
    case 2: info->frequency = 16; break;
    case 3: info->frequency = (config < 14) ? 24 : 48; break;
    case 4: info->frequency = 8; break;
    case 5: info->frequency = 16; break;
    case 6: info->frequency = 24; break;
    default: info->frequency = 48; break;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3 || size > 1000000) return 0;

  // Using last byte as a number of streams (instead of rand_r). Each stream
  // should be at least 3 bytes long hence divmod.
  int streams = 1 + data[size - 1] % (size / 3);
  if (streams > 255) streams = 255;
  unsigned char *mapping = (unsigned char*) malloc(sizeof(unsigned char)*streams);
  if (!mapping) return 0;

  for (int i = 0; i < streams; ++i) {
    mapping[i] = i;
  }

  struct TocInfo info;
  extractTocInfo(*data, &info);

  int error = 0;
  OpusMSDecoder *const decoder = opus_multistream_decoder_create(
      info.frequency * 1000, streams, streams, 0, mapping, &error);

  if (!decoder || error) return 0;

  const int frame_size = (info.frequency * info.frame_len_x2) / 2;
  opus_int16 *pcm = (opus_int16*) malloc(sizeof(opus_int16)*frame_size*streams);
  if (!pcm) goto exit;

  // opus_decode wants us to use its return value, but we don't really care.
  const int foo =
      opus_multistream_decode(decoder, data, size, pcm, frame_size, 0);
  (void)foo;

  opus_multistream_decoder_destroy(decoder);

  free(pcm);

exit:
  free(mapping);
  return 0;
}
