#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "libdwarf/libdwarf.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *buf = (char*)Data;
    Dwarf_Unsigned leb128 = 0;
    Dwarf_Signed result = 0;
    char *endptr = buf + Size;
    dwarf_decode_signed_leb128(buf, &leb128, &result, endptr);
    return 0;
}
