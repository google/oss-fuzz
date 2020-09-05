#include <stddef.h>
#include <stdint.h>
#include "libyuv.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  // Fuzz the mjpeg_decoder
  libyuv::MJpegDecoder mjpeg_decoder;
  mjpeg_decoder.LoadFrame(data, size);

  return 0;
}
