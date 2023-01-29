#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixdata.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GdkPixdata pixdata;
    GError *error = NULL;
    if(!gdk_pixdata_deserialize(&pixdata, Size, Data, &error)) {
        g_error_free(error);
    }
    return 0;
}
