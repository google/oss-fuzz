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
    ucl_type_t type = (ucl_type_t)Data[0];
    ucl_object_t *obj = ucl_object_typed_new(type);
    if (obj) {
        ucl_object_unref(obj);
    }
    return 0;
}
