#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <Magick++/Blob.h>
#include <Magick++/Image.h>

class MagickFormats {
public:
  MagickFormats() {
    size_t nFormats;
    Magick::ExceptionInfo ex;
    const Magick::MagickInfo **formats = GetMagickInfoList("*", &nFormats, &ex);

    for (size_t i = 0; i < nFormats; i++) {
      const Magick::MagickInfo *format = formats[i];
      if (strcmp(format->name, "HTML") == 0) {
        continue;
      }
      if (format->encoder && format->name) {
        Formats.push_back(std::string(format->name));
      }
    }
  }

  std::vector<std::string> Formats;
};

const MagickFormats kFormats;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  const Magick::Blob blob(Data, Size);
  Magick::Image image;
  try {
    image.read(blob);
  } catch (Magick::Exception &e) {
    return 0;
  }
  for (auto &format : kFormats.Formats) {
    Magick::Blob outBlob;
    try {
      image.write(&outBlob, format.c_str());
    } catch (Magick::Exception &e) {
    }
  }
  return 0;
}
