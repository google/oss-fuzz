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
#include <limits.h>
#include <stddef.h>

#include <array>
#include <cmath>
#include <memory>

#include "../celt/mathops.h"
#include "../celt/os_support.h"
#include "opus.h"
#include "opus_defines.h"
#include "opus_projection.h"
#include "opus_types.h"

// Having a huge-size vastly reduces the fuzzer's speed
#define MAX_MATRIX_SIZE 4096

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  const int frame_size_ms_x2 =
      fdp.PickValueInArray({5, 10, 20, 40, 80, 120, 160, 200, 240});
  const opus_int32 frequency = fdp.PickValueInArray({8, 12, 16, 24, 48}) * 1000;
  const int frame_size = frame_size_ms_x2 * frequency / 2000;

  // The allowed number of channels is either n^2 or n^2 + 2
  opus_int32 nb_channels = pow(fdp.ConsumeIntegralInRange(0, 15), 2);
  if (fdp.ConsumeBool()) {
    nb_channels += 2;
  }
  const int streams = fdp.ConsumeIntegralInRange(0, 255);
  const int coupled_streams = fdp.ConsumeIntegralInRange(0, streams);

  const opus_int32 matrix_size = fdp.ConsumeIntegralInRange(1, MAX_MATRIX_SIZE);
  unsigned char *matrix = (unsigned char *)opus_alloc(matrix_size);
  if (matrix == NULL) {
    return 0;
  }

  fdp.ConsumeData(matrix, matrix_size);

  int err = OPUS_OK;
  OpusProjectionDecoder *const decoder = opus_projection_decoder_create(
      frequency, nb_channels, streams, coupled_streams, matrix, matrix_size,
      &err);
  opus_free(matrix);
  if (decoder == nullptr || err != OPUS_OK) {
    return 0;
  }
  bool use_float = fdp.ConsumeBool();
  bool use_fec = fdp.ConsumeBool();
  auto payload = fdp.ConsumeRemainingBytes<unsigned char>();
  const opus_int16 payload_size =
      std::min((unsigned long)SHRT_MAX, payload.size());

  if (use_float) {
    float *pcm =
        (float *)opus_alloc(sizeof(float) * frame_size * nb_channels);
    if (pcm == NULL) {
      goto end;
    }

    const int foo = opus_projection_decode_float(
        decoder, payload.data(), payload_size, pcm, frame_size, use_fec);
    (void)foo;
    opus_free(pcm);
  } else {
    opus_int16 *pcm =
        (opus_int16 *)opus_alloc(sizeof(opus_int16) * frame_size * nb_channels);
    if (pcm == NULL) {
      goto end;
    }

    const int foo = opus_projection_decode(
        decoder, payload.data(), payload_size, pcm, frame_size, use_fec);
    (void)foo;
    opus_free(pcm);
  }
end:
  opus_projection_decoder_destroy(decoder);

  return 0;
}
