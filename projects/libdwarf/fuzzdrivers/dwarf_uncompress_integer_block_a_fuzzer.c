#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "libdwarf/libdwarf.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    Dwarf_Debug dw_dbg = 0;
    Dwarf_Unsigned dw_input_length_in_bytes = Size;
    Dwarf_Unsigned * dw_value_count = 0;
    Dwarf_Signed ** dw_value_array = 0;
    Dwarf_Error * dw_error = 0;
    dwarf_uncompress_integer_block_a(dw_dbg, dw_input_length_in_bytes, (void*)Data, dw_value_count, dw_value_array, dw_error);
    return 0;
}
