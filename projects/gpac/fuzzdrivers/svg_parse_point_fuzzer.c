#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/scenegraph_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    SVG_Point p;
    char * value_string = malloc(Size + 1);
    memcpy(value_string, Data, Size);
    value_string[Size] = 0;
    GF_Err e;
    svg_parse_point(&p, value_string, &e);
    free(value_string);
    return 0;  // Non-zero return values are reserved for future use.
}
