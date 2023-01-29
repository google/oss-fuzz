#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "jpeglib.h"
#include "turbojpeg.h"
#include "turbojpeg.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    tjhandle handle = tjInitDecompress();
    int width, height;
    tjDecompressHeader(handle, (unsigned char *)Data, (unsigned long)Size, &width, &height);
    tjDestroy(handle);
    return 0;
}
