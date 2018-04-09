#include <msgpack.hpp>
#include <assert.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    msgpack::object_handle result = msgpack::unpack(reinterpret_cast<const char *>(data), size);
    msgpack::object obj = result.get();
  } catch (...) {
  }
  return 0;
}
