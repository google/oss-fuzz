#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    turn_credential_type ct = (turn_credential_type)Data[0];
    uint8_t *buf = (uint8_t *)Data + 1;
    size_t len = Size - 1;
    const uint8_t *uname = (const uint8_t *)"";
    const uint8_t *realm = (const uint8_t *)"";
    const uint8_t *upwd = (const uint8_t *)"";
    SHATYPE shatype = (SHATYPE)Data[1];

    stun_check_message_integrity_str(ct, buf, len, uname, realm, upwd, shatype);
    return 0;
}
