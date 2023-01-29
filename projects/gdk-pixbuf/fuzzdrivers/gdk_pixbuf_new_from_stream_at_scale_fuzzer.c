#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixbuf-core.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GInputStream *stream = g_memory_input_stream_new_from_data(Data, Size, NULL);
    GdkPixbuf *pixbuf = gdk_pixbuf_new_from_stream_at_scale(stream, 100, 100, TRUE, NULL, NULL);
    g_object_unref(pixbuf);
    g_object_unref(stream);
    return 0;
}
