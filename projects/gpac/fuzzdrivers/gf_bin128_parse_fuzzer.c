#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/tools.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *string = malloc(Size + 1);
    memcpy(string, Data, Size);
    string[Size] = '\0';
    bin128 value;
    gf_bin128_parse(string, value);
    free(string);
    return 0;
}
