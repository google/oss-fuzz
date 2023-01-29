#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixbuf-transform.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1)
        return 0;
    GdkPixbuf *src, *dest;
    GdkInterpType interp_type;
    int dest_x, dest_y, dest_width, dest_height, overall_alpha;
    double offset_x, offset_y, scale_x, scale_y;
    char *buf = (char *)malloc(Size * sizeof(char));
    memcpy(buf, Data, Size);
    src = gdk_pixbuf_new_from_data((const guchar *)buf, GDK_COLORSPACE_RGB, 1, 8, 1, 1, 1, NULL, NULL);
    if (src == NULL) {
        free(buf);
        return 0;
    }
    dest = gdk_pixbuf_new(GDK_COLORSPACE_RGB, 1, 8, 1, 1);
    if (dest == NULL) {
        free(buf);
        g_object_unref(src);
        return 0;
    }
    dest_x = dest_y = dest_width = dest_height = overall_alpha = 0;
    offset_x = offset_y = scale_x = scale_y = 0.0;
    interp_type = GDK_INTERP_NEAREST;
    gdk_pixbuf_composite(src, dest, dest_x, dest_y, dest_width, dest_height, offset_x, offset_y, scale_x, scale_y, interp_type, overall_alpha);
    free(buf);
    g_object_unref(src);
    g_object_unref(dest);
    return 0;
}
