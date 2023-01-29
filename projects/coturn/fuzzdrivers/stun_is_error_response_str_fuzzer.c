#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 20)
        return 0;
    int err_code;
    uint8_t err_msg[1024];
    stun_is_error_response_str(Data, Size, &err_code, err_msg, sizeof(err_msg));
    return 0;
}
