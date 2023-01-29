#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_insert_key(obj, ucl_object_fromstring("value"), "key", 3, false);
    ucl_object_lookup_len(obj, (const char *)Data, Size);
    ucl_object_unref(obj);
    return 0;
}
