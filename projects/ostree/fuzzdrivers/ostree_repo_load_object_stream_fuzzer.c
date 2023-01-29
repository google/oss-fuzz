#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ostree.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 64) return 0;
    g_autoptr(GError) error = NULL;
    g_autoptr(GInputStream) input = NULL;
    g_autoptr(GBytes) bytes = NULL;
    g_autoptr(OstreeRepo) repo = NULL;
    guint64 out_size = 0;
    g_autofree char *checksum = NULL;
    g_autoptr(GFile) file = NULL;
    g_autoptr(GFileInputStream) file_input = NULL;

    // create a temporary file
    file = g_file_new_tmp("fuzz-XXXXXX", &file_input, &error);
    if (file == NULL) return 0;
    // write the data to the file
    if (g_output_stream_write_all((GOutputStream *)file_input, Data, Size, NULL, NULL, &error) == FALSE) {
        return 0;
    }
    // create a new ostree repo
    repo = ostree_repo_new(file);
    if (ostree_repo_create(repo, OSTREE_REPO_MODE_ARCHIVE_Z2, NULL, &error) == FALSE) {
        return 0;
    }
    // commit the temporary file to the repo
    if (ostree_repo_write_content(repo, NULL, Data, Size, &checksum, NULL, &error) == FALSE) {
        return 0;
    }
    // load the object stream from the repo
    if (ostree_repo_load_object_stream(repo, OSTREE_OBJECT_TYPE_FILE, checksum, &input, &out_size, NULL, &error) == FALSE) {
        return 0;
    }
    // read the object stream
    bytes = g_input_stream_read_bytes(input, out_size, NULL, &error);
    if (bytes == NULL) {
        return 0;
    }
    return 0;
}
