#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ostree.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    g_autoptr(GInputStream) out_input = NULL;
    g_autoptr(GFileInfo) out_file_info = NULL;
    g_autoptr(GVariant) out_xattrs = NULL;
    gboolean compressed = TRUE;
    gboolean trusted = TRUE;
    const char * path = "/tmp/fuzzed_file";
    int parent_dfd = 0;
    GCancellable * cancellable = NULL;
    GError * error = NULL;
    // write the fuzzed data to a file
    FILE *f = fopen(path, "wb");
    fwrite(Data, 1, Size, f);
    fclose(f);
    // call the function
    ostree_content_file_parse_at(compressed, parent_dfd, path, trusted, &out_input, &out_file_info, &out_xattrs, cancellable, &error);
    return 0;
}
