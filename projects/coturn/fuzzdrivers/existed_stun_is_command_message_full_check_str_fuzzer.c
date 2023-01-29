#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/client/ns_turn_msg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int must_check_fingerprint = 1;
    int fingerprint_present = 0;
    int ret = stun_is_command_message_full_check_str(Data, Size, must_check_fingerprint, &fingerprint_present);
    return 0;
}
