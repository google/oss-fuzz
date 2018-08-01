#include <stdint.h>
#include "glib/glib.h"

static GMarkupParser parser = {
    NULL, NULL, NULL, NULL, NULL,
};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  g_autoptr(GMarkupParseContext) ctx =
      g_markup_parse_context_new(&parser, 0, NULL, NULL);

  // Parses incrementally in chunks.

  const uint8_t* new_data = data;
  size_t new_size = (size % 0x200) + 1;

  while (1) {
    if (new_data + new_size > data + size)
      new_size = data + size - new_data;
    if (!g_markup_parse_context_parse(
        ctx, (const gchar*)new_data, new_size, NULL)) {
      break;
    }
    if (!new_size) {
      g_markup_parse_context_end_parse(ctx, NULL);
      break;
    }
    new_data += new_size;
    new_size += size % 0x10;
  }

  return 0;
}
