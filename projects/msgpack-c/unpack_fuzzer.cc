#include <msgpack.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    msgpack::object_handle unpacked = msgpack::unpack(reinterpret_cast<const char *>(data),
                                                      size,
                                                      nullptr,
                                                      nullptr,
                                                      msgpack::unpack_limit(100, 100, 100, 1000));
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, unpacked.get());
  } catch (...) {
  }
  return 0;
}
