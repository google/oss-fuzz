// The fuzzer takes as input a buffer of bytes. The buffer is read in as:
// <angle>, <x_center>, <y_center>, and the remaining bytes will be read
// in as a <pix>. The image is then rotated by angle around the center. All
// inputs should not result in undefined behavior.
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "leptonica/allheaders.h"

namespace {

// Reads the front bytes of a data buffer containing `size` bytes as an int16_t,
// and advances the buffer forward [if there is sufficient capacity]. If there
// is insufficient capacity, this returns 0 and does not modify size or data.
int16_t ReadInt16(const uint8_t** data, size_t* size) {
  int16_t result = 0;
  if (*size >= sizeof(result)) {
    memcpy(&result, *data, sizeof(result));
    *data += sizeof(result);
    *size -= sizeof(result);
  }
  return result;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const int16_t angle = ReadInt16(&data, &size);
  const int16_t x_center = ReadInt16(&data, &size);
  const int16_t y_center = ReadInt16(&data, &size);

  Pix* pix = pixReadMem(reinterpret_cast<const unsigned char*>(data), size);
  if (pix == nullptr) {
    return EXIT_SUCCESS;
  }
  constexpr float deg2rad = M_PI / 180.;
  Pix* pix_rotated = pixRotateShear(pix, x_center, y_center, deg2rad * angle,
                                    L_BRING_IN_WHITE);
  if (pix_rotated) {
    pixDestroy(&pix_rotated);
  }

  pixDestroy(&pix);
  return EXIT_SUCCESS;
}
