#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixbuf-core.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GError *error = NULL;
    GInputStream *stream = g_memory_input_stream_new_from_data(Data, Size, NULL);
    GAsyncResult *async_result = g_simple_async_result_new(G_OBJECT(stream), NULL, NULL, NULL);
    g_simple_async_result_complete_in_idle(async_result);
    GdkPixbuf *pixbuf = gdk_pixbuf_new_from_stream_finish(async_result, &error);
    if (pixbuf)
        g_object_unref(pixbuf);
    if (error)
        g_error_free(error);
    g_object_unref(stream);
    g_object_unref(async_result);
    return 0;
}
