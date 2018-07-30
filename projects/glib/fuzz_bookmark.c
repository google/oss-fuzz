#include "glib/glib.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  g_autoptr(GBookmarkFile) bookmarkfile = g_bookmark_file_new();
  g_bookmark_file_load_from_data(bookmarkfile, (const gchar*)data, size, NULL);
  return 0;
}
