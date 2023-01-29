#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    if (Data[0] != '{') return 0;
    ucl_object_t *obj = ucl_object_fromstring_common(Data, Size, UCL_STRING_RAW);
    if (!obj) return 0;
    ucl_object_todouble(obj);
    ucl_object_unref(obj);
    return 0;
}
