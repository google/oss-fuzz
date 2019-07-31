#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "zopfli.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ZopfliOptions options;
  ZopfliInitOptions(&options);

  if (size == 0 || size > 1024) {
    return 0;
  }

  const ZopfliFormat format = static_cast<ZopfliFormat>(data[0] % 3);
  data++;
  size--;

  unsigned char* outbuf = nullptr;
  size_t outsize = 0;

  ZopfliCompress(&options, format, data, size, &outbuf, &outsize);

  if (outbuf != nullptr) {
    free(outbuf);
  }

  return 0;
}
