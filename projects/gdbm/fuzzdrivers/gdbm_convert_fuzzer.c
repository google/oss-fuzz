#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gdbm.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GDBM_FILE dbf;
    int flag;

    // check the size of the input
    if (Size < 2)
        return 0;

    // open the database file
    dbf = gdbm_open("gdbm_fuzz.db",0,GDBM_WRCREAT,0666,0);
    if (!dbf)
        return 0;

    // set the flag
    flag = Data[0];

    // write the data to the database file
    gdbm_convert(dbf,flag);

    // close the database file
    gdbm_close(dbf);

    return 0;
}
