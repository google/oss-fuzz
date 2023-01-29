#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int requested_address_family = 0;
    int error_code = 0;
    stun_attr_get_address_error_code((uint8_t *)Data, Size, &requested_address_family, &error_code);
    return 0;
}
