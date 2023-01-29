#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/scenegraph_svg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_Matrix2D mat;
    char * attribute_content = malloc(Size + 1);
    memcpy(attribute_content, Data, Size);
    attribute_content[Size] = 0;
    gf_svg_parse_transformlist(&mat, attribute_content);
    free(attribute_content);
    return 0;
}
