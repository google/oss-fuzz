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
    unsigned char *dstPlanes[3];
    int strides[3];
    if (tjDecompressToYUVPlanes(handle,Data,Size,dstPlanes,0,strides,0,0) == 0) {
        tjFree(dstPlanes[0]);
        tjFree(dstPlanes[1]);
        tjFree(dstPlanes[2]);
    }
    tjDestroy(handle);
    return 0;
}
