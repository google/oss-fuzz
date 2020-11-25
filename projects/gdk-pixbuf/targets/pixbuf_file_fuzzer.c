#include <stdint.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include "fuzzer_temp_file.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    GdkPixbuf *pixbuf;
    GError *error = NULL;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    pixbuf = gdk_pixbuf_new_from_file(tmpfile, &error);
    if (error != NULL) {
        g_clear_error(&error);
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    char *buf = (char *) malloc(size + 1);
    memcpy(buf, data, size);
    buf[size] = '\0';

    gdk_pixbuf_get_width(pixbuf);
    gdk_pixbuf_get_height(pixbuf);
    gdk_pixbuf_get_bits_per_sample(pixbuf);
    gdk_pixbuf_scale(pixbuf, pixbuf,
            0, 0, 
            gdk_pixbuf_get_width(pixbuf) / 4, 
            gdk_pixbuf_get_height(pixbuf) / 4,
            0, 0, 0.5, 0.5,
            GDK_INTERP_NEAREST);
    pixbuf = gdk_pixbuf_rotate_simple(pixbuf, 180);
    gdk_pixbuf_set_option(pixbuf, buf, buf);
    gdk_pixbuf_get_option(pixbuf, buf);

    free(buf);
    g_clear_object(&pixbuf);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
