#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    if (Size > 20) return 0;
    char *str = malloc(Size+1);
    memcpy(str, Data, Size);
    str[Size] = '\0';

    const char *json = "{\"key\": \"value\"}";
    ucl_object_t *obj = ucl_object_fromstring(json);
    ucl_object_lookup(obj, str);
    ucl_object_unref(obj);
    free(str);
    return 0;
}
