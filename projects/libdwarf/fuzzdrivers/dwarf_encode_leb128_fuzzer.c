#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "libdwarf/libdwarf.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2)
        return 0;
    int length = Data[0];
    int is_signed = Data[1];
    char *buf = malloc(length);
    if (!buf)
        return 0;
    dwarf_encode_leb128(0, &length, buf, is_signed);
    free(buf);
    return 0;
}
