// Fuzzer for libp2p multiselect message parser (backup version)
#include <cstddef>
#include <cstdint>
#include <span>

#include <libp2p/common/types.hpp>
#include <libp2p/protocol_muxer/multiselect/parser.hpp>

using libp2p::BytesIn;
using libp2p::protocol_muxer::multiselect::detail::Parser;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Parser parser;

  // Feed input in small chunks to exercise underflow/overflow paths
  size_t pos = 0;
  while (pos < size) {
    size_t step = 1;
    if (pos < size) {
      step = 1 + (data[pos] & 0x0F);  // 1..16
    }
    if (pos + step > size) {
      step = size - pos;
    }
    BytesIn chunk(data + pos, step);
    auto state = parser.consume(chunk);
    (void)state;
    pos += step;
  }

  // Finalize by resetting and consuming the whole buffer at once
  parser.reset();
  BytesIn all(data, size);
  (void)parser.consume(all);

  return 0;
}

