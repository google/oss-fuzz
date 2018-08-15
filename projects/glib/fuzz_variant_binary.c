#include "glib/glib.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  g_autoptr(GVariant) variant = g_variant_new_from_data(
      G_VARIANT_TYPE_VARIANT, data, size, FALSE, NULL, NULL);
  if (!variant)
    return 0;
  g_variant_get_normal_form(variant);
  g_variant_get_data(variant);
  return 0;
}
