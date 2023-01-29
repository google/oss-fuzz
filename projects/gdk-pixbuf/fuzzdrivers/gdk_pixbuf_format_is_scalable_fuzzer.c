#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixbuf-io.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *data = (char *)malloc(Size + 1);
    memcpy(data, Data, Size);
    data[Size] = 0;

    GdkPixbufFormat *format = gdk_pixbuf_get_file_info(data, NULL, NULL);
    if (format)
        gdk_pixbuf_format_is_scalable(format);

    free(data);
    return 0;
}
