// Minimal fuzzer for Multihash parsing
#include <cstddef>
#include <cstdint>

#include <libp2p/multi/multihash.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == nullptr || size == 0) {
    return 0;
  }
  libp2p::BytesIn in{data, size};
  auto res = libp2p::multi::Multihash::createFromBytes(in);
  if (res) {
    // Exercise a couple of methods on success
    auto mh = res.value();
    (void)mh.toHex();
    (void)mh.toBuffer();
  }
  return 0;
}

