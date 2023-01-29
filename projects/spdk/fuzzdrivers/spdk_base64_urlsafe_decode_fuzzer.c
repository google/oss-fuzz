#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "spdk/base64.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    size_t dst_len = 0;
    char *dst = NULL;
    char *src = NULL;
    src = (char *) malloc(Size + 1);
    memcpy(src, Data, Size);
    src[Size] = 0;
    spdk_base64_urlsafe_decode(dst, &dst_len, src);
    free(src);
    return 0;
}
