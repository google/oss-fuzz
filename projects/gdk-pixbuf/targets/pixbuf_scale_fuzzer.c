#include <stdint.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include "fuzzer_temp_file.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    GError *error = NULL;
    GdkPixbuf *pixbuf;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    pixbuf = gdk_pixbuf_new_from_file_at_scale(tmpfile, 1, size, TRUE, &error);
    g_clear_error(&error);
    pixbuf = gdk_pixbuf_new_from_file_at_scale(tmpfile, 1, size, FALSE, &error);
    if (pixbuf != NULL) {
        g_clear_object(&pixbuf);
    } else {
        g_clear_error(&error);
    }
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
