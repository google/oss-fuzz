#include <cstdint>

#include <Magick++/Blob.h>
#include <Magick++/Image.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if ((sizeof(uint16_t) * 2) < 4) {
    return 0;
  }
  size_t Width = *reinterpret_cast<const uint16_t *>(Data);
  size_t Height = *reinterpret_cast<const uint16_t *>(Data + sizeof(uint16_t));
  const Magick::Blob blob(Data + (sizeof(uint16_t) * 2),
                          Size - (sizeof(uint16_t) * 2));
  Magick::Image image;
  try {
    image.read(blob);
  } catch (Magick::Exception &e) {
    return 0;
  }
  image.crop(Magick::Geometry(Width, Height));
  return 0;
}
