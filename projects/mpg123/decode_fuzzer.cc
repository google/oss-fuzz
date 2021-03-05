#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "mpg123.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool initialized = false;
  if (!initialized) {
    mpg123_init();
    initialized = true;
  }
  int ret;
  mpg123_handle* handle = mpg123_new(nullptr, &ret);
  if (handle == nullptr) {
    return 0;
  }

  ret = mpg123_param(handle, MPG123_ADD_FLAGS, MPG123_QUIET, 0.);
  if(ret == MPG123_OK)
    ret = mpg123_open_feed(handle);
  if (ret != MPG123_OK) {
    mpg123_delete(handle);
    return 0;
  }

  std::vector<uint8_t> output_buffer(mpg123_outblock(handle));

  size_t output_written = 0;
  // Initially, start by feeding the decoder more data.
  int decode_ret = MPG123_NEED_MORE;
  FuzzedDataProvider provider(data, size);
  while ((decode_ret != MPG123_ERR)) {
    if (decode_ret == MPG123_NEED_MORE) {
      if (provider.remaining_bytes() == 0
          || mpg123_tellframe(handle) > 10000
          || mpg123_tell_stream(handle) > 1<<20) {
        break;
      }
      const size_t next_size = provider.ConsumeIntegralInRange<size_t>(
          0,
          provider.remaining_bytes());
      auto next_input = provider.ConsumeBytes<unsigned char>(next_size);
      decode_ret = mpg123_decode(handle, next_input.data(), next_input.size(),
                                 output_buffer.data(), output_buffer.size(),
                                 &output_written);
    } else if (decode_ret != MPG123_ERR && decode_ret != MPG123_NEED_MORE) {
      decode_ret = mpg123_decode(handle, nullptr, 0, output_buffer.data(),
                                 output_buffer.size(), &output_written);
    } else {
      // Unhandled mpg123_decode return value.
      abort();
    }
  }

  mpg123_delete(handle);

  return 0;
}
