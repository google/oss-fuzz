#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "oniguruma.h"
#include "oniggnu.h"
#include "oniguruma.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    OnigEncoding enc = ONIG_ENCODING_UTF8;
    const OnigUChar * s = Data;
    const OnigUChar * end = Data + Size;
    onigenc_is_valid_mbc_string(enc, s, end);
    return 0;
}
