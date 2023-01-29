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
    int width = 640, height = 480, pixelSize = 3, pitch = width * pixelSize;
    unsigned char *dstBuf = (unsigned char *)malloc(pitch * height);
    tjhandle handle = tjInitDecompress();
    tjDecompress(handle, Data, Size, dstBuf, width, pitch, height, pixelSize, 0);
    tjDestroy(handle);
    free(dstBuf);
    return 0;  // Non-zero return values are reserved for future use.
}
