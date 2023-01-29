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
    unsigned char *jpegBuf = (unsigned char*) malloc(Size);
    unsigned char *dstBuf = (unsigned char*) malloc(3 * 4096 * 4096);
    if (jpegBuf == NULL || dstBuf == NULL) {
        return 0;
    }
    memcpy(jpegBuf, Data, Size);
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0;
    }
    tjDecompressToYUV(handle, jpegBuf, Size, dstBuf, 0);
    tjDestroy(handle);
    free(jpegBuf);
    free(dstBuf);
    return 0;
}
