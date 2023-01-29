#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "spdk/string.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size + 1);
    memcpy(str, Data, Size);
    str[Size] = '\0';
    spdk_strtoll(str, 10);
    free(str);
    return 0;
}
