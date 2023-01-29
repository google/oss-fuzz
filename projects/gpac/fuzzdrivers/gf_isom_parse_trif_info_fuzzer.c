#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/internal/isomedia_dev.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    u32 id, independent, x, y, w, h;
    Bool full_picture;
    gf_isom_parse_trif_info(Data, Size, &id, &independent, &full_picture, &x, &y, &w, &h);
    return 0;
}
