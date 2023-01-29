#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    stun_attr_get_first_channel_number_str(Data, Size);
    return 0;  // Non-zero return values are reserved for future use.
}
