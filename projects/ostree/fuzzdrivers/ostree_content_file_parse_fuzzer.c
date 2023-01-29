#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ostree.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    g_autoptr(GFile) content_path = NULL;
    g_autoptr(GInputStream) out_input = NULL;
    g_autoptr(GFileInfo) out_file_info = NULL;
    g_autoptr(GVariant) out_xattrs = NULL;

    content_path = g_file_new_for_path("/tmp/testfile");
    g_file_replace_contents(content_path, (const gchar *)Data, Size, NULL, FALSE, G_FILE_CREATE_NONE, NULL, NULL, NULL);

    ostree_content_file_parse(TRUE, content_path, TRUE, &out_input, &out_file_info, &out_xattrs, NULL, NULL);

    return 0;
}
