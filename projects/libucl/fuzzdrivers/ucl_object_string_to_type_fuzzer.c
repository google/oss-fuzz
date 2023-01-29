#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *input = (char *)malloc(Size + 1);
    memcpy(input, Data, Size);
    input[Size] = '\0';
    ucl_type_t res;
    ucl_object_string_to_type(input, &res);
    free(input);
    return 0;
}
