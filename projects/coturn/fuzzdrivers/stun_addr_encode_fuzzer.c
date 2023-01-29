#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg_addr.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ioa_addr ca;
    uint8_t cfield[256];
    int clen;
    uint32_t mc;
    uint8_t tsx_id[12];
    stun_addr_encode(&ca, cfield, &clen, 0, mc, tsx_id);
    return 0;
}
