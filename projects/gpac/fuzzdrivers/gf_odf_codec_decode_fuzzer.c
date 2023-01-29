#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/mpeg4_odf.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GF_ODCodec *codec = gf_odf_codec_new();
    gf_odf_codec_set_au(codec, Data, Size);
    gf_odf_codec_decode(codec);
    gf_odf_codec_del(codec);
    return 0;
}
