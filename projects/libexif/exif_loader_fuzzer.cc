#include <stdio.h>
#include <stdint.h>
#include <libexif/exif-loader.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  ExifLoader *loader = exif_loader_new();
  ExifData *data;
  if (!loader) {
    return 0;
  }
  exif_loader_write(loader, (unsigned char *)Data, Size);
  data = exif_loader_get_data(loader);
  if(!data) {
    exif_loader_unref(loader);
    return 0;
  }
  exif_loader_unref(loader);
  exif_data_unref(data);
  return 0;
}
