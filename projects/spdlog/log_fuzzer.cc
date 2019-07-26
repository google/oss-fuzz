#include <cstddef>

#include "FuzzedDataProvider.h"
#include "spdlog/spdlog.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) {
    return 0;
  }
  FuzzedDataProvider stream(data, size);

  const size_t size_arg = stream.ConsumeIntegral<size_t>();
  const int int_arg = stream.ConsumeIntegral<int>();
  const std::string string_arg = stream.ConsumeRandomLengthString(size);
  const std::string format_string = stream.ConsumeRemainingBytesAsString();
  spdlog::info(format_string.c_str(), size_arg, int_arg, string_arg);

  return 0;
}
