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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "opus.h"
#include "opus_types.h"
#include "opus_defines.h"

#define MAX_PACKET (1500)
#define SAMPLES (48000 * 10)
#define MAX_FRAME_SAMP (5760)

static const int sampling_rates[] = {8000, 12000, 16000, 24000, 48000};
static const int channels[] = {1, 2};
static const int applications[] = {OPUS_APPLICATION_AUDIO,
                                   OPUS_APPLICATION_VOIP,
                                   OPUS_APPLICATION_RESTRICTED_LOWDELAY};
static const int frame_sizes_ms_x2[] = {5, 10, 20, 40, 80, 120, 160, 200, 240};

static opus_int16 inbuf[sizeof(opus_int16) * SAMPLES] = {0};
static unsigned char packet[MAX_PACKET + 257];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  int err = OPUS_OK;
  int num_channels = fdp.PickValueInArray(channels);
  int frame_size = fdp.PickValueInArray(frame_sizes_ms_x2);
  int sampling_rate = fdp.PickValueInArray(sampling_rates);
  int application = fdp.PickValueInArray(applications);


  OpusEncoder *enc =
      opus_encoder_create(sampling_rate, num_channels, application, &err);
  if (err != OPUS_OK || enc == NULL) {
    opus_encoder_destroy(enc);
    return 0;
  }

  opus_encoder_ctl(enc, OPUS_SET_COMPLEXITY(fdp.ConsumeIntegralInRange(0, 10)));
  opus_encoder_ctl(enc, OPUS_SET_VBR(fdp.ConsumeBool()));
  opus_encoder_ctl(enc, OPUS_SET_VBR_CONSTRAINT(fdp.ConsumeBool()));
  opus_encoder_ctl(
      enc, OPUS_SET_FORCE_CHANNELS(fdp.PickValueInArray({OPUS_AUTO, 1, 2})));
  opus_encoder_ctl(enc,
                   OPUS_SET_MAX_BANDWIDTH(fdp.PickValueInArray(
                       {OPUS_BANDWIDTH_NARROWBAND, OPUS_BANDWIDTH_MEDIUMBAND,
                        OPUS_BANDWIDTH_WIDEBAND, OPUS_BANDWIDTH_SUPERWIDEBAND,
                        OPUS_BANDWIDTH_FULLBAND})));
  opus_encoder_ctl(enc, OPUS_SET_INBAND_FEC(fdp.ConsumeBool()));
  opus_encoder_ctl(
      enc, OPUS_SET_PACKET_LOSS_PERC(fdp.ConsumeIntegralInRange(0, 100)));
  opus_encoder_ctl(enc, OPUS_SET_DTX(fdp.ConsumeBool()));
  opus_encoder_ctl(enc, OPUS_SET_LSB_DEPTH(fdp.ConsumeIntegralInRange(8, 24)));
  opus_encoder_ctl(enc, OPUS_SET_PREDICTION_DISABLED((fdp.ConsumeBool())));
  opus_encoder_ctl(enc,
                   OPUS_SET_SIGNAL(fdp.PickValueInArray(
                       {OPUS_AUTO, OPUS_SIGNAL_VOICE, OPUS_SIGNAL_MUSIC})));
  opus_encoder_ctl(enc,
                   OPUS_SET_PHASE_INVERSION_DISABLED(((fdp.ConsumeBool()))));

  fdp.ConsumeData(inbuf, sizeof(inbuf));

  size_t samp_count = 0;
  do {
    const int frame_size_samples = frame_size * sampling_rate / 2000;

    const int len = opus_encode(enc, &inbuf[samp_count * num_channels],
                                frame_size_samples, packet, MAX_PACKET);
    if (len < 0 || len > MAX_PACKET) {
      break;
    }
    samp_count += frame_size;
  } while (samp_count < ((SAMPLES / 2) - MAX_FRAME_SAMP));

  opus_encoder_destroy(enc);

  return 0;
}
