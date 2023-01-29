#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "oniguruma.h"
#include "oniggnu.h"
#include "oniguruma.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    OnigRegex re;
    OnigRegion *region;
    int r;
    const uint8_t *start = Data;
    const uint8_t *end = Data + Size;

    r = onig_new(&re, start, end, ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, NULL);
    if (r != ONIG_NORMAL) {
        return 0;
    }

    region = onig_region_new();
    onig_search(re, start, end, start, end, region, ONIG_OPTION_NONE);
    onig_region_free(region, 1);
    onig_free(re);
    return 0;
}
