/* Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <string.h>
#include <cstdint>
#include "ivorbiscodec.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 10) return 0;

  vorbis_info vi;
  vorbis_comment vc;
  vorbis_info_init(&vi);
  vorbis_comment_init(&vc);

  const uint8_t *ptr = Data;
  size_t remaining = Size;

  // We'll use the first 3 "packets" for headers
  for (int i = 0; i < 3; ++i) {
    if (remaining < 2) break;
    size_t p_size = (ptr[0] << 8) | ptr[1];
    ptr += 2;
    remaining -= 2;
    if (p_size > remaining) p_size = remaining;
    
    if (p_size > 0) {
      ogg_packet op;
      op.packet = (unsigned char *)ptr;
      op.bytes = p_size;
      op.b_o_s = (i == 0);
      op.e_o_s = 0;
      op.granulepos = 0;
      op.packetno = i;
      
      vorbis_synthesis_headerin(&vi, &vc, &op);
      
      ptr += p_size;
      remaining -= p_size;
    }
  }

  vorbis_dsp_state vd;
  if (vorbis_synthesis_init(&vd, &vi) == 0) {
    vorbis_block vb;
    vorbis_block_init(&vd, &vb);
    
    while (remaining > 2) {
      size_t p_size = (ptr[0] << 8) | ptr[1];
      ptr += 2;
      remaining -= 2;
      if (p_size > remaining) p_size = remaining;

      if (p_size > 0) {
        ogg_packet op;
        op.packet = (unsigned char *)ptr;
        op.bytes = p_size;
        op.b_o_s = 0;
        op.e_o_s = (remaining == p_size);
        op.granulepos = -1;
        op.packetno = 0;

        if (vorbis_synthesis(&vb, &op) == 0) {
          vorbis_synthesis_blockin(&vd, &vb);
        }
        
        ogg_int32_t **pcm;
        int samples = vorbis_synthesis_pcmout(&vd, &pcm);
        if (samples > 0) {
          vorbis_synthesis_read(&vd, samples);
        }

        ptr += p_size;
        remaining -= p_size;
      }
    }
    vorbis_block_clear(&vb);
    vorbis_dsp_clear(&vd);
  }

  vorbis_info_clear(&vi);
  vorbis_comment_clear(&vc);
  
  return 0;
}
