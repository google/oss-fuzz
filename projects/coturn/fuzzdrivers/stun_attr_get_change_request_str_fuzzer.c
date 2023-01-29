#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    stun_attr_ref attr = stun_attr_get_first_str(Data, Size);
    int change_ip;
    int change_port;
    stun_attr_get_change_request_str(attr, &change_ip, &change_port);
    return 0;
}
