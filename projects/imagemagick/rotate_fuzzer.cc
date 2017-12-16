#include <cstdint>

#include <Magick++/Blob.h>
#include <Magick++/Image.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 8) {
    return 0;
  }
  double Degrees = *reinterpret_cast<const double *>(Data);
  if (!isfinite(Degrees)) {
    return 0;
  }
  const Magick::Blob blob(Data + 8, Size - 8);
  Magick::Image image;
  try {
    image.read(blob);
  } catch (Magick::Exception &e) {
    return 0;
  }
  image.rotate(Degrees);
  return 0;
}
