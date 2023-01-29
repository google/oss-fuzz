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
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_insert_key(obj, ucl_object_fromlstring((const char *)Data, Size), (const char *)Data, Size, true);
    ucl_object_type(obj);
    ucl_object_unref(obj);
    return 0;
}
