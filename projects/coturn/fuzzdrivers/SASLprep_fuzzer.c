#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint8_t *s = (uint8_t *) malloc(Size + 1);
    memcpy(s, Data, Size);
    s[Size] = '\0';
    SASLprep(s);
    free(s);
    return 0;
}
