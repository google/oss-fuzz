#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "oniguruma.h"
#include "oniggnu.h"
#include "oniguruma.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2)
        return 0;

    OnigRegex reg;
    OnigErrorInfo einfo;
    int r;

    r = onig_new(&reg, Data, Data + Size, ONIG_OPTION_DEFAULT, ONIG_ENCODING_UTF8, ONIG_SYNTAX_DEFAULT, &einfo);
    if (r != ONIG_NORMAL) {
        onig_free(reg);
        return 0;
    }

    OnigRegion *region = onig_region_new();
    r = onig_match(reg, Data, Data + Size, Data, region, ONIG_OPTION_NONE);
    onig_region_free(region, 1);
    onig_free(reg);

    return 0;
}
