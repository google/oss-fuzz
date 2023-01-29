#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "libdwarf/libdwarf.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    Dwarf_Unsigned val = 0;
    Dwarf_Unsigned len = 0;
    char *end = (char *) Data + Size;
    dwarf_decode_leb128((char *) Data, &val, &len, end);
    return 0;
}
