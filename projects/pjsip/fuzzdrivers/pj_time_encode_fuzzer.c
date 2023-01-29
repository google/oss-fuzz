#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "pjlib-util.h"
#include "pjlib.h"
#include "pjmedia-codec.h"
#include "pjmedia.h"
#include "pjmedia_audiodev.h"
#include "pjmedia_videodev.h"
#include "pjnath.h"
#include "pjsip.h"
#include "pjsip_simple.h"
#include "pjsip_ua.h"
#include "pjsua.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size != sizeof(pj_parsed_time))
        return 0;

    pj_parsed_time pt;
    pj_time_val tv;
    memcpy(&pt, Data, Size);
    pj_time_encode(&pt, &tv);

    return 0;
}
