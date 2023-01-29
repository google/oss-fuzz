#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "pg_query.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char * input = malloc(Size + 1);
    memcpy(input, Data, Size);
    input[Size] = 0;

    PgQueryParseResult result = pg_query_parse(input);

    pg_query_free_parse_result(result);

    free(input);

    return 0;
}
