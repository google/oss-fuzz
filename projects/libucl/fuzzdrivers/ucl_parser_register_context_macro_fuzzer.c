#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;
    struct ucl_parser * parser = ucl_parser_new(0);
    ucl_parser_register_context_macro(parser, Data, NULL, NULL);
    ucl_parser_free(parser);
    return 0;
}
