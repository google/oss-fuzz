#include "glib/glib.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  g_autoptr(GKeyFile) keyfile = g_key_file_new();
  g_key_file_load_from_data(keyfile, (const gchar*)data, size, 0, NULL);
  return 0;
}
