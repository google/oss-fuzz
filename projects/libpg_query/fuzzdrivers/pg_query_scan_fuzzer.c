#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "pg_query.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *input = (char *) malloc(Size + 1);
    memcpy(input, Data, Size);
    input[Size] = 0;
    PgQueryScanResult result = pg_query_scan(input);
    free(input);
    pg_query_free_scan_result(result);
    return 0;
}
