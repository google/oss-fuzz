#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "mpg123.h"
#include "byte_stream.h"

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
  ByteStream stream(data, size);
  while ((decode_ret != MPG123_ERR)) {
    if (decode_ret == MPG123_NEED_MORE) {
      if (stream.capacity() == 0) {
        break;
      }
      const size_t next_size = std::min(stream.GetNextSizeT(), stream.capacity());
      uint8_t* next_input = (uint8_t*)malloc(sizeof(uint8_t) * next_size);
      memcpy(next_input, stream.UncheckedConsume(next_size), next_size);
      decode_ret = mpg123_decode(
          handle, reinterpret_cast<const unsigned char*>(next_input),
          next_size, output_buffer.data(), output_buffer.size(),
          &output_written);
      free(next_input);
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
