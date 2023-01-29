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
    if (Size < 2) return 0;
    int width = Data[0];
    int height = Data[1];
    int pitch = width * 3;
    int pixelFormat = TJPF_RGB;
    int flags = 0;
    int pad = 0;
    int subsamp = 0;
    unsigned char * dstBuf = (unsigned char *)malloc(width * height * 3);
    int ret = tjDecodeYUV(NULL, Data, pad, subsamp, dstBuf, width, pitch, height, pixelFormat, flags);
    free(dstBuf);
    return 0;
}
