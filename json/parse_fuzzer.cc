#include <iostream>
#include <sstream>
#include <json.hpp>

using json = nlohmann::json;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  try {
    std::stringstream s;
    s << json::parse(data, data + size);
    try {
      auto j2 = json::parse(s.str());
    } catch (const std::invalid_argument&) { 
      std::cerr << std::string{data, data + size} << " -> " << s.str() << "\n";
      assert(0);
    }
  } catch (const std::invalid_argument&) { }
  return 0;
}
