#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "sepol/policydb/policydb.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    sepol_handle_t * handle = sepol_handle_create();
    policydb_t * policydb = NULL;
    int ret = policydb_from_image(handle, (void*)Data, Size, policydb);
    sepol_handle_destroy(handle);
    return ret;
}
