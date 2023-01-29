#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ucl_object_t *obj;
    char *path;
    const ucl_object_t *ret;

    if (Size < 1) {
        return 0;
    }

    path = malloc(Size + 1);
    if (!path) {
        return 0;
    }

    memcpy(path, Data, Size);
    path[Size] = '\0';

    obj = ucl_object_typed_new(UCL_OBJECT);
    if (!obj) {
        return 0;
    }

    ret = ucl_object_lookup_path(obj, path);

    ucl_object_unref(obj);
    free(path);

    return 0;
}
