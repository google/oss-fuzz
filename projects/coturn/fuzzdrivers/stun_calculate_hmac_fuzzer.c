#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4)
        return 0;
    uint8_t key[4];
    uint8_t hmac[20];
    unsigned int hmac_len;
    memcpy(key, Data, 4);
    stun_calculate_hmac(Data + 4, Size - 4, key, 4, hmac, &hmac_len, SHATYPE_SHA1);
    return 0;
}
