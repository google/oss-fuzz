// Minimal fuzzer for Multiaddress parsing
#include <cstddef>
#include <cstdint>
#include <string>

#include <libp2p/multi/multiaddress.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (data == nullptr || size == 0) {
    return 0;
  }
  std::string s(reinterpret_cast<const char *>(data), size);

  // Multiaddress strings typically start with '/'. Ensure both paths are tested.
  auto try_parse = [](std::string_view str) {
    auto res = libp2p::multi::Multiaddress::create(str);
    if (res) {
      const auto &ma = res.value();
      (void)ma.getStringAddress();
      (void)ma.getBytesAddress();
      (void)ma.getPeerId();
      (void)ma.getProtocols();
      (void)ma.getProtocolsWithValues();
      (void)ma.splitFirst();
    }
  };

  try_parse(s);
  if (!s.empty() && s.front() != '/') {
    s.insert(s.begin(), '/');
    try_parse(s);
  }
  return 0;
}

