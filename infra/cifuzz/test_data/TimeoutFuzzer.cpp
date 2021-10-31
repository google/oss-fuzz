#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
  while (true)
    ;
  return 0;
}
