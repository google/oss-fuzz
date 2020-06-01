#include <stddef.h>
#include <stdint.h>

#include <string>

#include <libraw.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  LibRaw lib_raw;

  int err = lib_raw.open_buffer(
      const_cast<char*>(reinterpret_cast<const char*>(data)), size);
  if (err != LIBRAW_SUCCESS) {
    return 0;
  }

  err = lib_raw.unpack();
  if (err != LIBRAW_SUCCESS) {
    return 0;
  }

  err = lib_raw.dcraw_process();
  if (err != LIBRAW_SUCCESS) {
    return 0;
  }

  return 0;
}