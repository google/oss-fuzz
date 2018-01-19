/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <cstdint>

#include <mupdf/fitz.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fz_context *ctx = fz_new_context(nullptr, nullptr, FZ_STORE_DEFAULT);
  fz_register_document_handlers(ctx);

  fz_stream *stream = fz_open_memory(ctx, data, size);
  fz_matrix ctm;
  fz_pixmap *pix;
  fz_try(ctx) {
    fz_document *doc = fz_open_document_with_stream(ctx, "pdf", stream);
    for (int i = 0; i < fz_count_pages(ctx, doc); i++) {
      pix = fz_new_pixmap_from_page_number(ctx, doc, i, &ctm, fz_device_rgb(ctx), 0);
      fz_drop_pixmap(ctx, pix);
    }
    fz_drop_document(ctx, doc);
  }
  fz_catch(ctx) {}

  fz_drop_stream(ctx, stream);
  fz_drop_context(ctx);

  return 0;
}
