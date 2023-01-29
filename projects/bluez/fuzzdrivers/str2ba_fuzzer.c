#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "bluetooth/bluetooth.h"
#include "bluetooth/bnep.h"
#include "bluetooth/cmtp.h"
#include "bluetooth/hci.h"
#include "bluetooth/hci_lib.h"
#include "bluetooth/hidp.h"
#include "bluetooth/l2cap.h"
#include "bluetooth/rfcomm.h"
#include "bluetooth/sco.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"
#include "bluetooth/bluetooth.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    bdaddr_t ba;
    char *str = (char *)malloc(Size + 1);
    if (!str)
        return 0;
    memcpy(str, Data, Size);
    str[Size] = 0;
    str2ba(str, &ba);
    free(str);
    return 0;
}
