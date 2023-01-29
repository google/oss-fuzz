#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "utf8proc.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    utf8proc_int32_t state = 0;
    utf8proc_int32_t codepoint1 = 0;
    utf8proc_int32_t codepoint2 = 0;

    for (size_t i = 0; i < Size; i++) {
        codepoint1 = codepoint2;
        codepoint2 = Data[i];

        utf8proc_grapheme_break_stateful(codepoint1, codepoint2, &state);
    }

    return 0;
}
