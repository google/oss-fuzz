#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "ucl.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Make sure we have at least one byte of data.
    if (Size < 1) return 0;
    // Make sure that the last byte is 0.
    if (Data[Size-1] != 0) return 0;

    // Create a ucl object.
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    // Insert a key-value pair.
    ucl_object_insert_key(obj, ucl_object_fromstring("value"), "key", 0, false);

    // Call the function to be tested.
    ucl_object_lookup_path_char(obj, (const char *)Data, '.');

    // Free the ucl object.
    ucl_object_unref(obj);

    return 0;
}
