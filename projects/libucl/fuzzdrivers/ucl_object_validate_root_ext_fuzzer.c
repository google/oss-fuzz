#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;
    ucl_object_t *schema = ucl_object_fromlstring(Data, Size / 2);
    ucl_object_t *obj = ucl_object_fromlstring(Data + Size / 2, Size - Size / 2);
    ucl_object_t *ext_refs = ucl_object_typed_new(UCL_OBJECT);
    struct ucl_schema_error err;
    ucl_object_validate_root_ext(schema, obj, obj, ext_refs, &err);
    ucl_object_unref(schema);
    ucl_object_unref(obj);
    ucl_object_unref(ext_refs);
    return 0;
}
