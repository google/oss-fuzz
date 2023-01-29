#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixbuf-io.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }
    char *buffer = (char *)malloc(Size + 1);
    memcpy(buffer, Data, Size);
    buffer[Size] = '\0';
    GdkPixbufFormat * format = gdk_pixbuf_get_file_info(buffer, NULL, NULL);
    gdk_pixbuf_format_is_save_option_supported(format, buffer);
    free(buffer);
    return 0;
}
