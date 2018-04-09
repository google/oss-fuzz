#include <msgpack.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  msgpack::sbuffer sbuf;
  msgpack::packer<msgpack::sbuffer> packer(sbuf);
  packer.pack_bin(size);

  const char *input = (const char *) data;
  packer.pack_bin_body(input, size);

  return 0;
}
