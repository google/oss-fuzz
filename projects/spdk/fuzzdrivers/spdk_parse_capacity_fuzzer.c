#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "spdk/string.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint64_t cap;
    _Bool has_prefix;
    char *cap_str = malloc(Size + 1);
    memcpy(cap_str, Data, Size);
    cap_str[Size] = '\0';
    spdk_parse_capacity(cap_str, &cap, &has_prefix);
    return 0;
}
