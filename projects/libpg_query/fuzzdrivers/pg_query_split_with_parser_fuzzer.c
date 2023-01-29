#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "pg_query.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *input = malloc(Size + 1);
    memcpy(input, Data, Size);
    input[Size] = '\0';

    PgQuerySplitResult result = pg_query_split_with_parser(input);
    pg_query_free_split_result(result);

    free(input);

    return 0;
}
