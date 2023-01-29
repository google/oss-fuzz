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
    int width, height, jpegSubsamp, jpegColorspace;
    tjDecompressHeader3(handle, Data, Size, &width, &height, &jpegSubsamp, &jpegColorspace);
    tjDestroy(handle);
    return 0;
}
