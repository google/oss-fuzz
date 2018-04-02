#include <stdio.h>
#include <stdint.h>
#include <libexif/exif-loader.h>


void content_func(ExifEntry *entry, void *user_data) {
  char buf[10000];
  exif_entry_get_value(entry, buf, sizeof(buf));
}

void data_func(ExifContent *content, void *user_data) {
  exif_content_foreach_entry(content, content_func, NULL);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ExifLoader *loader = exif_loader_new();
  ExifData *exif_data;
  if (!loader) {
    return 0;
  }
  exif_loader_write(loader, const_cast<unsigned char*>(data), size);
  exif_data = exif_loader_get_data(loader);
  if(!exif_data) {
    exif_loader_unref(loader);
    return 0;
  }
  exif_data_foreach_content(exif_data, data_func, NULL);
  exif_loader_unref(loader);
  exif_data_unref(exif_data);
  return 0;
}
