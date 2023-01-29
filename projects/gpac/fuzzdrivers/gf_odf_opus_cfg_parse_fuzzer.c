#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/mpeg4_odf.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_OpusConfig cfg;
    gf_odf_opus_cfg_parse(Data, Size, &cfg);
    return 0;
}
