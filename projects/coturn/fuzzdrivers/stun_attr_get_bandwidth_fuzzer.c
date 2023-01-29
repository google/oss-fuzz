#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8)  // this is the minimum size of a bandwidth attribute
        return 0;

    stun_attr_ref attr = (stun_attr_ref)Data;
    (void)stun_attr_get_bandwidth(attr);
    return 0;
}
