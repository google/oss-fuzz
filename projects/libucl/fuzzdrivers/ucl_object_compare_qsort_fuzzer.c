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

    ucl_object_t *obj1 = ucl_object_fromlstring((const char *)Data, Size / 2);
    ucl_object_t *obj2 = ucl_object_fromlstring((const char *)Data + Size / 2, Size / 2);

    ucl_object_compare_qsort(&obj1, &obj2);

    ucl_object_unref(obj1);
    ucl_object_unref(obj2);

    return 0;
}
