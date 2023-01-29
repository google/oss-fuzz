#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;
    const uint8_t *Data2 = Data + 1;
    size_t Size2 = Size - 1;
    ucl_object_t *schema = ucl_object_fromstring_common(Data, Size, UCL_STRING_PARSE);
    ucl_object_t *obj = ucl_object_fromstring_common(Data2, Size2, UCL_STRING_PARSE);
    struct ucl_schema_error err;
    ucl_object_validate(schema, obj, &err);
    ucl_object_unref(schema);
    ucl_object_unref(obj);
    return 0;
}
