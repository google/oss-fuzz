#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    size_t app_len;
    if (Size < 4) return 0;

    // check if the input is a valid stun message
    if (Data[0] != 0x00 || Data[1] != 0x01) return 0;
    if (Data[2] == 0x00 && Data[3] == 0x00) return 0;

    // fuzz the function
    stun_get_message_len_str((uint8_t *)Data, Size, 0, &app_len);

    return 0;
}
