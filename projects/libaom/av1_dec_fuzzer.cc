// Fuzzing of AV1 decoder.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aom/aom_decoder.h"
#include "aom/aomdx.h"
#include "aom_ports/mem_ops.h"
#include "aom/common/ivfdec.h"

static const char *const kIVFSignature = "DKIF";

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *const file = fmemopen((void *)data, size, "rb");
  if (file == nullptr) {
    return 0;
  }

  char header[32];
  if (fread(header, 1, 32, file) != 32) {
    return 0;
  }
  const AvxInterface *decoder = get_aom_decoder_by_name("av1");
  if (decoder == nullptr) {
    return 0;
  }

  aom_codec_ctx_t codec;

#if defined(DECODE_MODE_serial)
  const int threads = 1;
#elif defined(DECODE_MODE_threaded)
  const int threads = 16;
#else
#error define one of DECODE_MODE_(serial|threaded)
#endif
  aom_codec_dec_cfg_t cfg = {threads, 0, 0};
  if (aom_codec_dec_init(&codec, decoder->codec_interface(), &cfg, 0)) {
    aom_codec_destroy(&codec);
    return 0;
  }

  int frame_in_cnt = 0;
  int frame_out_cnt = 0;
  uint8_t *buffer = nullptr;
  size_t buffer_size = 0;
  size_t frame_size = 0;
  while (!ivf_read_frame(file, &buffer, &frame_size, &buffer_size, NULL)) {
    const aom_codec_err_t err = aom_codec_decode(
        &codec, buffer, static_cast<unsigned int>(frame_size), NULL);
    ++frame_in_cnt;
    aom_codec_iter_t iter = nullptr;
    aom_image_t *img = nullptr;
    while ((img = aom_codec_get_frame(&codec, &iter)) != nullptr) {
      ++frame_out_cnt;
    }
  }

  fclose(file);
  free(buffer);
  return 0;
}
