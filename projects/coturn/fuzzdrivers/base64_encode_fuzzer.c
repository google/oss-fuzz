#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "turn/apputils.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    size_t output_length = 0;
    char * encoded = base64_encode(Data, Size, &output_length);
    if (encoded) {
        free(encoded);
    }
    return 0;
}
