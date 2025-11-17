// Minimal fuzzer for Multibase decoding
#include <cstddef>
#include <cstdint>
#include <string>

#include <libp2p/multi/multibase_codec/multibase_codec_impl.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == nullptr || size == 0) {
    return 0;
  }
  std::string s(reinterpret_cast<const char *>(data), size);

  libp2p::multi::MultibaseCodecImpl codec;
  // Try decode as-is
  (void)codec.decode(s);

  // Also try with a valid prefix if missing, to reach deeper code paths.
  if (s.size() >= 1 && s[0] != 'f' && s[0] != 'F' && s[0] != 'b' &&
      s[0] != 'B' && s[0] != 'z' && s[0] != 'm') {
    s.insert(s.begin(), 'z');
    (void)codec.decode(s);
  }
  return 0;
}

