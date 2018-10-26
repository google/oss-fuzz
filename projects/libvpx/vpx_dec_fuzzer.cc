// Fuzzing of VPx decoder.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(DECODE_MODE_threaded)
#include <algorithm>
#endif
#include <memory>
#include "vpx_config.h"
#include "ivfdec.h"
#include "vpx/vpx_decoder.h"
#include "vpx_ports/mem_ops.h"
#include "tools_common.h"
#if CONFIG_VP8_DECODER || CONFIG_VP9_DECODER
#include "vpx/vp8dx.h"
#endif

static void close_file(FILE *file) { fclose(file); }

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::unique_ptr<FILE, decltype(&close_file)> file(
      fmemopen((void *)data, size, "rb"), &close_file);
  if (file == nullptr) {
    return 0;
  }

  char header[IVF_FILE_HDR_SZ];
  if (fread(header, 1, IVF_FILE_HDR_SZ, file.get()) != IVF_FILE_HDR_SZ) {
    return 0;
  }
#ifdef ENABLE_vp8
  const VpxInterface *decoder = get_vpx_decoder_by_name("vp8");
#else
  const VpxInterface *decoder = get_vpx_decoder_by_name("vp9");
#endif
  if (decoder == nullptr) {
    return 0;
  }

  vpx_codec_ctx_t codec;
#if defined(DECODE_MODE)
  const unsigned int threads = 1;
#elif defined(DECODE_MODE_threaded)
  // Set thread count in the range [2, 64].
  const unsigned int threads = std::max((header[0] & 0x3f) + 1, 2);
#else
#error define one of DECODE_MODE or DECODE_MODE_threaded
#endif
  vpx_codec_dec_cfg_t cfg = {threads, 0, 0};
  if (vpx_codec_dec_init(&codec, decoder->codec_interface(), &cfg, 0)) {
    return 0;
  }

  uint8_t *buffer = nullptr;
  size_t buffer_size = 0;
  size_t frame_size = 0;

  while (!ivf_read_frame(file.get(), &buffer, &frame_size, &buffer_size)) {
    const vpx_codec_err_t err =
        vpx_codec_decode(&codec, buffer, frame_size, nullptr, 0);
    static_cast<void>(err);
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t *img = nullptr;
    while ((img = vpx_codec_get_frame(&codec, &iter)) != nullptr) {
    }
  }
  vpx_codec_destroy(&codec);
  free(buffer);
  return 0;
}
