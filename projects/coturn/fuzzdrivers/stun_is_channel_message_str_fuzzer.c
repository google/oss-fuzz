#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint16_t chnumber;
    int mandatory_padding;
    size_t blen = Size;
    stun_is_channel_message_str(Data, &blen, &chnumber, mandatory_padding);
    return 0;
}
