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

// Fuzz harness for the libwebp demuxer (WebP container parser).
//
// The demuxer parses the RIFF container format used by all WebP files,
// including animated WebP (ANIM/ANMF chunks), metadata (ICCP, EXIF, XMP),
// and the extended file format (VP8X).  It is used by any application that
// needs to extract individual frames or metadata from a WebP bitstream without
// performing a full decode.
//
// Coverage:
//   WebPDemux()           – parse the container
//   WebPDemuxGetI()       – read parameters (width, height, frame count)
//   WebPDemuxGetFrame()   – iterate over all frames
//   WebPDemuxGetChunk()   – extract metadata chunks (ICCP, EXIF, XMP)

#include <cstddef>
#include <cstdint>

#include "src/webp/demux.h"
#include "src/webp/decode.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  WebPData webp_data = {data, size};

  WebPDemuxer *demux = WebPDemux(&webp_data);
  if (!demux) return 0;

  // Read top-level parameters.
  uint32_t width  = WebPDemuxGetI(demux, WEBP_FF_CANVAS_WIDTH);
  uint32_t height = WebPDemuxGetI(demux, WEBP_FF_CANVAS_HEIGHT);
  uint32_t flags  = WebPDemuxGetI(demux, WEBP_FF_FORMAT_FLAGS);
  (void)WebPDemuxGetI(demux, WEBP_FF_LOOP_COUNT);
  (void)WebPDemuxGetI(demux, WEBP_FF_BACKGROUND_COLOR);
  (void)WebPDemuxGetI(demux, WEBP_FF_FRAME_COUNT);

  // Guard against degenerate dimensions.
  if (width > 0 && height > 0 && width <= 16384 && height <= 16384) {
    // Iterate frames and optionally decode each one.
    WebPIterator iter;
    if (WebPDemuxGetFrame(demux, 1, &iter)) {
      do {
        // Decode the frame's compressed bitstream.
        int w, h;
        uint8_t *pixels = WebPDecodeRGBA(iter.fragment.bytes,
                                         iter.fragment.size, &w, &h);
        WebPFree(pixels);
      } while (WebPDemuxNextFrame(&iter));
      WebPDemuxReleaseIterator(&iter);
    }
  }

  // Extract metadata chunks.
  WebPChunkIterator chunk_iter;
  if ((flags & ICCP_FLAG) && WebPDemuxGetChunk(demux, "ICCP", 1, &chunk_iter))
    WebPDemuxReleaseChunkIterator(&chunk_iter);
  if ((flags & EXIF_FLAG) && WebPDemuxGetChunk(demux, "EXIF", 1, &chunk_iter))
    WebPDemuxReleaseChunkIterator(&chunk_iter);
  if ((flags & XMP_FLAG)  && WebPDemuxGetChunk(demux, "XMP ", 1, &chunk_iter))
    WebPDemuxReleaseChunkIterator(&chunk_iter);

  WebPDemuxDelete(demux);
  return 0;
}
