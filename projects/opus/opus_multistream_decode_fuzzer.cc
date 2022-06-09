// Copyright 2021 Google LLC
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

#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>

#include <algorithm>
#include <memory>
#include <random>

#include "../celt/mathops.h"
#include "../celt/os_support.h"
#include "opus.h"
#include "opus_defines.h"
#include "opus_multistream.h"
#include "opus_projection.h"
#include "opus_types.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  const int frame_size_ms_x2 =
      fdp.PickValueInArray({5, 10, 20, 40, 80, 120, 160, 200, 240});
  const opus_int32 frequency = fdp.PickValueInArray({8, 12, 16, 24, 48}) * 1000;
  const int frame_size = frame_size_ms_x2 * frequency / 2000;
  const opus_int32 nb_channels = fdp.ConsumeIntegralInRange(0, 255);
  const int streams = fdp.ConsumeIntegralInRange(0, 255);
  const int coupled_streams = fdp.ConsumeIntegralInRange(0, 255);
  const bool use_fec = fdp.ConsumeBool();
  const bool use_float = fdp.ConsumeBool();

  unsigned char *mapping = (unsigned char *)malloc(nb_channels);
  if (!mapping) {
    return 0;
  }
  for (unsigned char x = 0; x < nb_channels; ++x) {
    mapping[x] = fdp.ConsumeIntegralInRange(0, 255);
  }

  int err = OPUS_OK;
  OpusMSDecoder *const decoder = opus_multistream_decoder_create(
      frequency, nb_channels, streams, coupled_streams, mapping, &err);
  free(mapping);

  if (decoder == nullptr || err != OPUS_OK) {
    return 0;
  }
  auto payload = fdp.ConsumeRemainingBytes<unsigned char>();
  const opus_int16 payload_size =
      std::min((const unsigned long)SHRT_MAX, payload.size());

  if (use_float) {
    float *pcm = (float *)opus_alloc(sizeof(float) * frame_size * nb_channels);
    if (pcm == NULL) {
      goto end;
    }
    const int foo = opus_multistream_decode_float(
        decoder, payload.data(), payload_size, pcm, frame_size, use_fec);
    (void)foo;

    opus_free(pcm);
  } else {
    opus_int16 *pcm =
        (opus_int16 *)opus_alloc(sizeof(opus_int16) * frame_size * nb_channels);
    if (pcm == NULL) {
      goto end;
    }
    const int foo = opus_multistream_decode(
        decoder, payload.data(), payload_size, pcm, frame_size, use_fec);
    (void)foo;

    opus_free(pcm);
  }
end:
  opus_multistream_decoder_destroy(decoder);

  return 0;
}
