#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    const char *target;
    size_t tlen;
    if (Size > 0) {
        ucl_object_t *obj = ucl_object_fromlstring((const char *)Data, Size);
        if (obj != NULL) {
            ucl_object_tolstring_safe(obj, &target, &tlen);
            ucl_object_unref(obj);
        }
    }
    return 0;
}
