#include <msgpack.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    // NOTE(derwolfe): by default the limits are set at 2^32-1 length. I'm
    // setting these at far smaller values to avoid OOMs
    const int test_limit = 10000;
    msgpack::object_handle unpacked = msgpack::unpack(reinterpret_cast<const char *>(data),
                                                      size,
                                                      nullptr,
                                                      nullptr,
                                                      msgpack::unpack_limit(test_limit,
                                                                            test_limit,
                                                                            test_limit,
                                                                            test_limit));
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, unpacked.get());
  } catch (...) {
  }
  return 0;
}
