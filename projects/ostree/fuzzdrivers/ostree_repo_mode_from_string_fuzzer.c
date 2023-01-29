#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ostree.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    OstreeRepoMode out_mode;
    char *mode = malloc(Size + 1);
    memcpy(mode, Data, Size);
    mode[Size] = 0;
    GError *error = NULL;
    gboolean ret = ostree_repo_mode_from_string(mode, &out_mode, &error);
    free(mode);
    return 0;
}
