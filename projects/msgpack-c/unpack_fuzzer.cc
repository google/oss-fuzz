#include <msgpack.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    msgpack::object_handle result = \
      msgpack::unpack(reinterpret_cast<const char *>(data), size);

    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, result.get());
  } catch (...) {
  }
  return 0;
}
