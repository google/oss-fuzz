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

#define MAX_PACKETOUT 32000

static opus_uint32 char_to_int(const unsigned char ch[4]) {
  return ((opus_uint32)ch[0] << 24) | ((opus_uint32)ch[1] << 16) |
         ((opus_uint32)ch[2] << 8) | (opus_uint32)ch[3];
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  unsigned char output_packet[MAX_PACKETOUT];
  OpusRepacketizer *rp = opus_repacketizer_create();
  opus_repacketizer_init(rp);
  const size_t nb_packets_to_add = fdp.ConsumeIntegralInRange(1, 48);
  const auto packets = fdp.ConsumeRemainingBytes<unsigned char>();

  size_t start = 0;
  for (size_t i = 0; i < nb_packets_to_add; i++) {
    if (packets.size() - start < 4) {
      break;
    }
    const size_t packet_length = char_to_int(packets.data() + start);
    start += 4;

    if (packets.size() - start < packet_length || packet_length > 1500) {
      break;
    }

    opus_repacketizer_cat(rp, packets.data() + start, packet_length);
    start += packet_length;
  }
  int foo = opus_repacketizer_out(rp, output_packet, MAX_PACKETOUT);
  (void)foo;

  opus_repacketizer_destroy(rp);

  return 0;
}
