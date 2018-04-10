#include <msgpack.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    msgpack::object_handle result = \
      msgpack::unpack(reinterpret_cast<const char *>(data), size);
    msgpack::object obj = result.get();

    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, obj);
  } catch (...) {
  }
  return 0;
}
