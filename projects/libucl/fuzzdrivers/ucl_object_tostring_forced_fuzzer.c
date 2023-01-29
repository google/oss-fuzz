#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }
    char *buf = (char *)malloc(Size + 1);
    memcpy(buf, Data, Size);
    buf[Size] = 0;
    ucl_object_t *obj = ucl_object_fromstring(buf);
    ucl_object_tostring_forced(obj);
    ucl_object_unref(obj);
    free(buf);
    return 0;
}
