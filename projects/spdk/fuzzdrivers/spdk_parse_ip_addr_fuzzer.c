#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "spdk/string.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *ip = (char *)malloc(Size + 1);
    if (!ip) {
        return 0;
    }
    memcpy(ip, Data, Size);
    ip[Size] = 0;
    char *host = NULL;
    char *port = NULL;
    spdk_parse_ip_addr(ip, &host, &port);
    free(ip);
    return 0;
}
