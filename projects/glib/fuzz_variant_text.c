#include "glib/glib.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const gchar* gdata = (const gchar*)data;
  g_autoptr(GVariant) variant =
      g_variant_parse(NULL, gdata, gdata + size, NULL, NULL);
  if (!variant)
    return 0;
  g_autofree gchar* text = g_variant_print(variant, TRUE);
  return 0;
}
