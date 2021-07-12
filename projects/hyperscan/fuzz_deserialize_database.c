#include "hs.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

FILE * logfile = NULL;


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (logfile == NULL) {
        logfile = fopen("/dev/null", "wb");
    }

    hs_database_t *database;
    hs_error_t err = hs_deserialize_database(Data, Size, &database);
    if (err != HS_SUCCESS) {
        fprintf(logfile, "ERROR\n");
        return 0;
    }
    hs_free_database(database);
    return 0;
}
