#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint32_t cookie = 0;
    old_stun_is_command_message_str(Data, Size, &cookie);
    return 0;
}
