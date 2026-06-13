// Copyright 2026 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

// Fuzz harness for the libwebp mux API (WebP container builder/parser).
//
// WebPMux is used to assemble and disassemble WebP containers, including
// attaching metadata (ICCP, EXIF, XMP) and building multi-frame animations.
// The read path (WebPMuxCreate) parses an arbitrary WebP bitstream and
// populates the mux object, exercising the same container-parsing logic as
// the RIFF reader and chunk dispatcher.
//
// Coverage:
//   WebPMuxCreate()        – parse an arbitrary WebP bitstream into a Mux
//   WebPMuxGetChunk()      – read metadata chunks
//   WebPMuxGetFrame()      – read the primary image or animation frames
//   WebPMuxGetCanvasSize() – read canvas dimensions

#include <cstddef>
#include <cstdint>

#include "src/webp/mux.h"
#include "src/webp/mux_types.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  WebPData webp_data = {data, size};

  // Parse the bitstream into a mux object.
  WebPMux *mux = WebPMuxCreate(&webp_data, /*copy_data=*/0);
  if (!mux) return 0;

  // Read canvas dimensions.
  int width, height;
  WebPMuxGetCanvasSize(mux, &width, &height);

  // Read primary/animation frame.
  WebPMuxFrameInfo frame;
  WebPDataInit(&frame.bitstream);
  if (WebPMuxGetFrame(mux, 1, &frame) == WEBP_MUX_OK) {
    WebPDataClear(&frame.bitstream);
  }

  // Read optional metadata chunks.
  WebPData chunk;
  WebPDataInit(&chunk);
  if (WebPMuxGetChunk(mux, "ICCP", &chunk) == WEBP_MUX_OK)
    WebPDataClear(&chunk);
  WebPDataInit(&chunk);
  if (WebPMuxGetChunk(mux, "EXIF", &chunk) == WEBP_MUX_OK)
    WebPDataClear(&chunk);
  WebPDataInit(&chunk);
  if (WebPMuxGetChunk(mux, "XMP ", &chunk) == WEBP_MUX_OK)
    WebPDataClear(&chunk);

  WebPMuxDelete(mux);
  return 0;
}
