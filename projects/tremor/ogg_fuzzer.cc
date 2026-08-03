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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ogg/ogg.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10) return 0;

  // Use the first few bytes to decide what to do
  uint8_t action = data[0];
  uint32_t serial = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
  const uint8_t *fuzz_data = data + 5;
  size_t fuzz_size = size - 5;

  // Fuzz ogg_sync and ogg_stream
  ogg_sync_state oy;
  ogg_stream_state os;
  ogg_sync_init(&oy);
  ogg_stream_init(&os, serial);

  char *buf = ogg_sync_buffer(&oy, fuzz_size);
  if (buf) {
    memcpy(buf, fuzz_data, fuzz_size);
    ogg_sync_wrote(&oy, fuzz_size);
  }

  ogg_page og;
  while (ogg_sync_pageout(&oy, &og) == 1) {
    ogg_stream_pagein(&os, &og);
    ogg_packet op;
    while (ogg_stream_packetout(&os, &op) == 1) {
      // Successfully extracted a packet
    }
  }

  ogg_stream_clear(&os);
  ogg_sync_clear(&oy);

  // Fuzz oggpack (bitwise) - LSb
  oggpack_buffer opb;
  oggpack_writeinit(&opb);
  
  size_t pos = 0;
  while (pos + 5 <= fuzz_size) {
    uint8_t op_choice = fuzz_data[pos++];
    uint32_t val = (fuzz_data[pos] << 24) | (fuzz_data[pos+1] << 16) | (fuzz_data[pos+2] << 8) | fuzz_data[pos+3];
    pos += 4;
    
    switch (op_choice % 4) {
      case 0:
        oggpack_write(&opb, val, fuzz_data[pos-1] % 33);
        break;
      case 1:
        oggpack_writealign(&opb);
        break;
      case 2:
        oggpack_writecopy(&opb, (void*)(fuzz_data + pos), (fuzz_size - pos) * 8);
        pos = fuzz_size; // consume rest
        break;
      case 3:
        oggpack_reset(&opb);
        break;
    }
  }
  
  // Read back what we wrote
  unsigned char *out_buf = oggpack_get_buffer(&opb);
  long out_bytes = oggpack_bytes(&opb);
  if (out_buf && out_bytes > 0) {
    oggpack_buffer opr;
    oggpack_readinit(&opr, out_buf, out_bytes);
    for (int i = 0; i < 10; ++i) {
        oggpack_look(&opr, 10);
        oggpack_adv(&opr, 1);
        oggpack_read(&opr, 8);
    }
  }
  oggpack_writeclear(&opb);

  // Fuzz oggpackB (bitwise) - MSb
  oggpackB_writeinit(&opb);
  pos = 0;
  while (pos + 5 <= fuzz_size) {
    uint8_t op_choice = fuzz_data[pos++];
    uint32_t val = (fuzz_data[pos] << 24) | (fuzz_data[pos+1] << 16) | (fuzz_data[pos+2] << 8) | fuzz_data[pos+3];
    pos += 4;
    
    switch (op_choice % 4) {
      case 0:
        oggpackB_write(&opb, val, fuzz_data[pos-1] % 33);
        break;
      case 1:
        oggpackB_writealign(&opb);
        break;
      case 2:
        oggpackB_writecopy(&opb, (void*)(fuzz_data + pos), (fuzz_size - pos) * 8);
        pos = fuzz_size; // consume rest
        break;
      case 3:
        oggpackB_reset(&opb);
        break;
    }
  }
  out_buf = oggpackB_get_buffer(&opb);
  out_bytes = oggpackB_bytes(&opb);
  if (out_buf && out_bytes > 0) {
    oggpack_buffer opr;
    oggpackB_readinit(&opr, out_buf, out_bytes);
    for (int i = 0; i < 10; ++i) {
        oggpackB_look(&opr, 10);
        oggpackB_adv(&opr, 1);
        oggpackB_read(&opr, 8);
    }
  }
  oggpackB_writeclear(&opb);

  return 0;
}
