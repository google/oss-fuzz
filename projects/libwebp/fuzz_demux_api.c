#include "fuzz.h"
#include "webp/mux.h"
#include "webp/demux.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  WebPData webp_data;
  WebPDataInit(&webp_data);
  webp_data.size = size;
  webp_data.bytes = data;

  // Extracted chunks and frames are not processed or decoded,
  // which is already covered extensively by the other fuzz targets.

  if (size & 1) {
    // Mux API
    WebPMux* mux = WebPMuxCreate(&webp_data, size & 2);
    if (!mux)
      return 0;

    WebPData chunk;
    WebPMuxGetChunk(mux, "EXIF", &chunk);
    WebPMuxGetChunk(mux, "ICCP", &chunk);
    WebPMuxGetChunk(mux, "FUZZ", &chunk); // unknown

    uint32_t flags;
    WebPMuxGetFeatures(mux, &flags);

    WebPMuxAnimParams params;
    WebPMuxGetAnimationParams(mux, &params);

    WebPMuxError status;
    WebPMuxFrameInfo info;
    for (int i = 0; i < fuzz_frame_limit; i++) {
      status = WebPMuxGetFrame(mux, i + 1, &info);
      if (status == WEBP_MUX_NOT_FOUND) {
        break;
      } else if (status == WEBP_MUX_OK) {
        WebPDataClear(&info.bitstream);
      }
    }

    WebPMuxDelete(mux);
  } else {
    // Demux API
    WebPDemuxer* demux;
    if (size & 2) {
      WebPDemuxState state;
      demux = WebPDemuxPartial(&webp_data, &state);
      if (state < WEBP_DEMUX_PARSED_HEADER) {
        WebPDemuxDelete(demux);
        return 0;
      }
    } else {
      demux = WebPDemux(&webp_data);
      if (!demux)
        return 0;
    }

    WebPChunkIterator chunk_iter;
    if (WebPDemuxGetChunk(demux, "EXIF", 1, &chunk_iter))
      WebPDemuxNextChunk(&chunk_iter);
    WebPDemuxReleaseChunkIterator(&chunk_iter);
    if (WebPDemuxGetChunk(demux, "ICCP", 0, &chunk_iter)) // 0 == last
      WebPDemuxPrevChunk(&chunk_iter);
    WebPDemuxReleaseChunkIterator(&chunk_iter);
    // Skips FUZZ because the Demux API has no concept of (un)known chunks.

    WebPIterator iter;
    if (WebPDemuxGetFrame(demux, 1, &iter)) {
      for (int i = 1; i < fuzz_frame_limit; i++) {
        if (!WebPDemuxNextFrame(&iter))
          break;
      }
    }

    WebPDemuxReleaseIterator(&iter);
    WebPDemuxDelete(demux);
  }

  return 0;
}
