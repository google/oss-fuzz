#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ostree.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char * out_remote = NULL;
    char * out_ref = NULL;
    char * refspec = malloc(Size + 1);
    memcpy(refspec, Data, Size);
    refspec[Size] = '\0';
    GError * error = NULL;
    gboolean ret = ostree_parse_refspec(refspec, &out_remote, &out_ref, &error);
    free(refspec);
    if (ret) {
        free(out_remote);
        free(out_ref);
    } else {
        g_error_free(error);
    }
    return 0;
}
