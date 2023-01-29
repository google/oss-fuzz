#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "sepol/policydb/policydb.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    policydb_t *p = calloc(1, sizeof(policydb_t));
    if (!p) {
        return 0;
    }
    struct policy_file *fp = calloc(1, sizeof(struct policy_file));
    if (!fp) {
        free(p);
        return 0;
    }
    fp->type = PF_USE_MEMORY;
    fp->data = Data;
    fp->len = Size;
    policydb_init(p);
    policydb_read(p, fp, 0);
    policydb_destroy(p);
    free(p);
    free(fp);
    return 0;
}
