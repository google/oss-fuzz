#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    struct ucl_parser * parser = ucl_parser_new(0);
    ucl_parser_add_fd_priority(parser, *Data, *Data);
    ucl_parser_free(parser);
    return 0;
}
