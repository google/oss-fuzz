#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "pg_query.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Create a null-terminated string from the input data.
    char *Input = (char *)malloc(Size + 1);
    if (!Input)
        return 0;
    memcpy(Input, Data, Size);
    Input[Size] = 0;

    // Call pg_query_parse_protobuf
    PgQueryProtobufParseResult result = pg_query_parse_protobuf(Input);

    // Clean up
    pg_query_free_protobuf_parse_result(result);
    free(Input);

    return 0;
}
