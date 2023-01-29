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
    if (Size < 8) return 0;
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;
    const unsigned char *srcPlanes[3];
    int strides[3];
    unsigned char *dstBuf;
    int width, pitch, height, pixelFormat, flags;
    int ret = tjDecodeYUVPlanes(handle, srcPlanes, strides, 1, dstBuf, width, pitch, height, pixelFormat, flags);
    tjDestroy(handle);
    return 0;
}
