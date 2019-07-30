#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "zopfli.h"
#include "FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);
  ZopfliOptions options;
  ZopfliInitOptions(&options);

  const ZopfliFormat format = stream.PickValueInArray(
    {ZOPFLI_FORMAT_GZIP, ZOPFLI_FORMAT_ZLIB, ZOPFLI_FORMAT_DEFLATE});

  unsigned char* outbuf = nullptr;
  size_t outsize = 0;
  std::string input = stream.ConsumeRemainingBytesAsString();
  ZopfliCompress(&options, format,
                 reinterpret_cast<const unsigned char*>(input.data()),
                 input.size(), &outbuf, &outsize);

  if (outbuf != nullptr) {
    free(outbuf);
  }

  return 0;
}
