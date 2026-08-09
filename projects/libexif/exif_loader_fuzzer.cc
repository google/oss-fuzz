// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

static void
test_exif_data (ExifData *d) {
  unsigned int i, c;
  char v[1024], *p;
  ExifMnoteData *md;

  md = exif_data_get_mnote_data (d);
  if (!md) {
    return;
  }

  exif_mnote_data_ref (md);
  exif_mnote_data_unref (md);

  c = exif_mnote_data_count (md);
  for (i = 0; i < c; i++) {
    const char *name = exif_mnote_data_get_name (md, i);
    if (!name) {
      break;
    }
    exif_mnote_data_get_title (md, i);
    exif_mnote_data_get_description (md, i);
    exif_mnote_data_get_value (md, i, v, sizeof (v));
  }
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
  test_exif_data (exif_data);
  exif_loader_unref(loader);
  exif_data_unref(exif_data);
  return 0;
}
