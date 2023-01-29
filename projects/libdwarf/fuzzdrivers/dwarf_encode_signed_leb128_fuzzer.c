#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "libdwarf/libdwarf.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;
    int out_size;
    char *out = (char *)malloc(Size);
    dwarf_encode_signed_leb128((Dwarf_Signed)Data[0], &out_size, out, (int)Data[1]);
    free(out);
    return 0;
}
