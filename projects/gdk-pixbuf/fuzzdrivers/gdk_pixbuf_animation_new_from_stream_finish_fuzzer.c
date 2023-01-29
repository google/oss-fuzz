#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixbuf-animation.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GError *error = NULL;
    GInputStream *stream = g_memory_input_stream_new_from_data(Data, Size, NULL);
    GdkPixbufAnimation *animation = gdk_pixbuf_animation_new_from_stream_finish(G_ASYNC_RESULT(stream), &error);
    if (animation) g_object_unref(animation);
    if (error) g_error_free(error);
    return 0;
}
