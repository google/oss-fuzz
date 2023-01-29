#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint16_t attr_type = 0;
    ioa_addr ca;
    ioa_addr default_addr;
    stun_attr_get_first_addr_str(Data, Size, attr_type, &ca, &default_addr);
    return 0;
}
