#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lws_config.h"
#include "libwebsockets.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *string = (char *)malloc(Size+1);
    memcpy(string, Data, Size);
    string[Size] = '\0';
    lws_urldecode(string, string, Size);
    free(string);
    return 0;
}
