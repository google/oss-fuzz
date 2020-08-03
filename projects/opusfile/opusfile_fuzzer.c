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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "opusfile/config.h"
#include "opusfile/include/opusfile.h"

// Opusfile fuzzing wrapper to help with automated fuzz testing. It's based on
// https://github.com/xiph/opusfile/blob/master/examples/opusfile_example.c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int ret, tmp;
  OggOpusFile *of = op_open_memory(data, size, &ret);
  if (!of)
    return 0;

  op_link_count(of);

  int link_index = -1;
  op_pcm_total(of, link_index);
  op_raw_total(of, link_index);
  op_pcm_tell(of);
  op_raw_tell(of);

  ogg_int64_t total_sample_count = 0;
  const int pcm_size = 120 * 48 * 2; // 120ms/ch@48kHz is recommended
  opus_int16 pcm[pcm_size];
  for (;;) {
    ret = op_read_stereo(of, pcm, pcm_size);
    if (ret < 0) {
      break;
    }

    if (op_current_link(of) != link_index) {
      link_index = op_current_link(of);
      op_pcm_total(of, link_index);
      op_raw_total(of, link_index);
      op_pcm_tell(of);
      op_raw_tell(of);
      op_bitrate_instant(of);
      tmp = op_head(of, link_index)->version;

      const OpusTags *tags = op_tags(of, link_index);
      for (int i = 0; i < tags->comments; ++i) {
        // Note: The compare also touches memory allocated for user_comments[i].
        // This is a desired side effect and should be kept even if this
        // comparison is removed.
        if (opus_tagncompare("METADATA_BLOCK_PICTURE", 22,
                             tags->user_comments[i]) == 0) {
          OpusPictureTag pic;
          if (opus_picture_tag_parse(&pic, tags->user_comments[i]) >= 0) {
            opus_picture_tag_clear(&pic);
          }
        }
      }

      if (tags->vendor) {
        tmp = tags->vendor[0];
      }

      int binary_suffix_len;
      opus_tags_get_binary_suffix(tags, &binary_suffix_len);
    }

    if (ret == 0) {
      break;
    }

    total_sample_count += ret;
  }

  if (total_sample_count > 0) {
    // Try random-access PCM reads. The number of tests is arbitrary and the
    // offset is designed to be pseudo-random, but deterministic - this is
    // implemented using Lehmer RNG with a minor hack that probably breaks some
    // properties of the RNG (but that is acceptable).
    ogg_int64_t rng_seed = 1307832949LL;
    for (int i = 0; i < 32; ++i) {
      // Derive the next deterministic offset to test and iterate the RNG.
      rng_seed = (rng_seed * 279470273LL);
      const ogg_int64_t offset = rng_seed % total_sample_count;
      rng_seed = rng_seed % 4294967291LL;

      if (op_pcm_seek(of, offset) == 0) {
        tmp = op_read_stereo(of, pcm, pcm_size);
      }
    }
  }

  op_free(of);
  return 0;
}
