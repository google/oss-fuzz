#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include "config.h"
#include "opus/opusfile.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    OpusHead head;
    opus_head_parse(&head, Data, Size);
    return 0;
}
