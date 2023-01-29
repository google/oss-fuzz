#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdbm.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;
    GDBM_FILE dbf = gdbm_open("test", 512, GDBM_WRCREAT, 0644, 0);
    if (dbf == NULL) return 0;
    FILE *fp = fmemopen((void *)Data, Size, "r");
    if (fp == NULL) return 0;
    int flag = Data[0];
    gdbm_import_from_file(dbf, fp, flag);
    gdbm_close(dbf);
    fclose(fp);
    return 0;
}
