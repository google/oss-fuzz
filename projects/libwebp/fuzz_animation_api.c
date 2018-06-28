#include "fuzz.h"
#include "webp/decode.h"
#include "webp/demux.h"
#include "webp/mux_types.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  WebPData webp_data;
  WebPDataInit(&webp_data);
  webp_data.size = size;
  webp_data.bytes = data;

  // WebPAnimDecoderNew uses WebPDemux internally to calloc canvas size.
  WebPDemuxer* demux = WebPDemux(&webp_data);
  if (!demux)
    return 0;
  uint32_t cw = WebPDemuxGetI(demux, WEBP_FF_CANVAS_WIDTH);
  uint32_t ch = WebPDemuxGetI(demux, WEBP_FF_CANVAS_HEIGHT);
  if ((size_t)cw * ch > fuzz_px_limit) {
    WebPDemuxDelete(demux);
    return 0;
  }

  // In addition to canvas size, check each frame separately.
  WebPIterator iter;
  for (int i = 0; i < fuzz_frame_limit; i++) {
    if (!WebPDemuxGetFrame(demux, i + 1, &iter))
      break;
    int w, h;
    if (WebPGetInfo(iter.fragment.bytes, iter.fragment.size, &w, &h)) {
      if ((size_t)w * h > fuzz_px_limit) { // image size of the frame payload
        WebPDemuxReleaseIterator(&iter);
        WebPDemuxDelete(demux);
        return 0;
      }
    }
  }

  WebPDemuxReleaseIterator(&iter);
  WebPDemuxDelete(demux);

  WebPAnimDecoderOptions dec_options;
  if (!WebPAnimDecoderOptionsInit(&dec_options))
    return 0;

  dec_options.use_threads = size & 1;
  // Animations only support 4 (of 12) modes.
  dec_options.color_mode = (WEBP_CSP_MODE)(size % MODE_LAST);
  if (dec_options.color_mode != MODE_BGRA &&
      dec_options.color_mode != MODE_rgbA &&
      dec_options.color_mode != MODE_bgrA) {
    dec_options.color_mode = MODE_RGBA;
  }

  WebPAnimDecoder* dec = WebPAnimDecoderNew(&webp_data, &dec_options);
  if (!dec)
    return 0;

  for (int i = 0; i < fuzz_frame_limit; i++) {
    uint8_t* buf;
    int timestamp;
    if (!WebPAnimDecoderGetNext(dec, &buf, &timestamp))
      break;
  }

  WebPAnimDecoderDelete(dec);
  return 0;
}
