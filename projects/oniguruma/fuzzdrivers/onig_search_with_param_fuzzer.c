#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "oniguruma.h"
#include "oniggnu.h"
#include "oniguruma.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    OnigRegex reg;
    OnigRegion *region;
    OnigMatchParam *mp;
    int r;
    int i;
    OnigUChar* str;
    OnigUChar* end;
    OnigUChar* start;
    OnigUChar* range;
    OnigOptionType option;
    OnigErrorInfo einfo;

    r = onig_new(&reg, Data, Data + Size, ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &einfo);
    if (r != ONIG_NORMAL) {
        return 0;
    }
    region = onig_region_new();
    mp = onig_new_match_param();
    str = (OnigUChar*)Data;
    end = (OnigUChar*)Data + Size;
    start = (OnigUChar*)Data;
    range = (OnigUChar*)Data + Size;
    option = ONIG_OPTION_NONE;
    onig_search_with_param(reg, str, end, start, range, region, option, mp);
    onig_region_free(region, 1);
    onig_free(reg);
    onig_free_match_param(mp);
    return 0;
}
