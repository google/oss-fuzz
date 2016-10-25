// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <hb.h>
#include <hb-ot.h>

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* dataPtr = reinterpret_cast<const char*>(data);
  hb_blob_t* blob = hb_blob_create(dataPtr, size, HB_MEMORY_MODE_READONLY, NULL,
                                   NULL);
  hb_face_t* face = hb_face_create(blob, 0);
  hb_font_t* font = hb_font_create(face);
  hb_ot_font_set_funcs(font);
  hb_font_set_scale(font, 12, 12);

  {
    const char text[] = "ABCDEXYZ123@_%&)*$!";
    hb_buffer_t* buffer = hb_buffer_create();
    hb_buffer_add_utf8(buffer, text, -1, 0, -1);
    hb_buffer_guess_segment_properties(buffer);
    hb_shape(font, buffer, NULL, 0);
    hb_buffer_destroy(buffer);
  }

  uint32_t text32[16] = { 0 };
  if (size > sizeof(text32)) {
    memcpy(text32, data + size - sizeof(text32), sizeof(text32));
    hb_buffer_t* buffer = hb_buffer_create();
    size_t text32len = sizeof(text32) / sizeof(text32[0]);
    hb_buffer_add_utf32(buffer, text32, text32len, 0, -1);
    hb_buffer_guess_segment_properties(buffer);
    hb_shape(font, buffer, NULL, 0);
    hb_buffer_destroy(buffer);
  }

  hb_font_destroy(font);
  hb_face_destroy(face);
  hb_blob_destroy(blob);
  return 0;
}
