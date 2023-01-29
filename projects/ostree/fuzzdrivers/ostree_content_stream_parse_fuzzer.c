#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ostree.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GInputStream *in = g_memory_input_stream_new_from_data(Data, Size, NULL);
    GInputStream *out = NULL;
    GFileInfo *file_info = NULL;
    GVariant *xattrs = NULL;
    gboolean ret = ostree_content_stream_parse(TRUE, in, Size, TRUE, &out, &file_info, &xattrs, NULL, NULL);
    g_object_unref(in);
    g_object_unref(out);
    g_object_unref(file_info);
    g_object_unref(xattrs);
    return ret;
}
