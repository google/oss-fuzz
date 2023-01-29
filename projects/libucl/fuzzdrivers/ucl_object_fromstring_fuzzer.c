#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return 0;
    }

    char *str = (char *)malloc(Size + 1);
    if (str == NULL) {
        return 0;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';

    ucl_object_t *obj = ucl_object_fromstring(str);
    ucl_object_unref(obj);
    free(str);
    return 0;
}
