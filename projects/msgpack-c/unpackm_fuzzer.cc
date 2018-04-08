#include <msgpack.hpp>
#include <assert.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char * input = (const char *) data;

  // pack the data manually
  msgpack::sbuffer sbuf;
  msgpack::packer<msgpack::sbuffer> packer(sbuf);
  packer.pack_bin(size);
  packer.pack_bin_body(input, size);

  //msgpack::unpack(serialized, deserialized);
  //bool same = memcmp(deserialized, buffer);
  //assert(same);

  return 0;
}
