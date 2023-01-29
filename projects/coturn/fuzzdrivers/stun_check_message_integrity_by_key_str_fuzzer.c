#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return 0;
    }
    uint8_t *buf = (uint8_t *)Data;
    size_t len = Size;
    hmackey_t key;
    password_t pwd;
    SHATYPE shatype;
    stun_check_message_integrity_by_key_str(0,buf,len,key,pwd,shatype);
    return 0;
}
