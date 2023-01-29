#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "spdk/trace_parser.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    struct spdk_trace_parser_opts opts;
    spdk_trace_parser_init(&opts);
    return 0;
}
