#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int err_code;
    uint8_t err_msg[1024];
    uint8_t realm[1024];
    uint8_t nonce[1024];
    uint8_t server_name[1024];
    int oauth;
    stun_is_challenge_response_str(Data, Size, &err_code, err_msg, 1024, realm, nonce, server_name, &oauth);
    return 0;
}
