#include <stdint.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include "fuzzer_temp_file.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    GError *error = NULL;
    GdkPixbuf *pixbuf;
    GdkPixbufAnimation *anim;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    anim = gdk_pixbuf_animation_new_from_file(tmpfile, &error);
    if (error != NULL) {
        g_clear_error(&error);
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    char *buf = (char *) malloc(size + 1);
    memcpy(buf, data, size);
    buf[size] = '\0';

    pixbuf = gdk_pixbuf_animation_get_static_image(anim);
    if (pixbuf != NULL) {
        pixbuf = gdk_pixbuf_rotate_simple(pixbuf, 180);
        gdk_pixbuf_set_option(pixbuf, buf, buf);
        gdk_pixbuf_get_pixels(pixbuf);
        gdk_pixbuf_get_width(pixbuf);
        gdk_pixbuf_get_height(pixbuf);
        g_object_unref(pixbuf);
    }

    free(buf);
    g_object_unref(anim);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
