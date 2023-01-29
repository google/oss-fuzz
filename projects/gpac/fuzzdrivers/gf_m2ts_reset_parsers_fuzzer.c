#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/mpegts.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;
    GF_M2TS_Demuxer *demux = gf_m2ts_demux_new(Data[0], Data[1]);
    if (demux) {
        gf_m2ts_reset_parsers(demux);
        gf_m2ts_demux_del(demux);
    }
    return 0;
}
