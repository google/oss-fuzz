#include <stdint.h>
#include <stdlib.h>

#include <turbojpeg.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tjhandle jpegDecompressor = tjInitDecompress();

    int width, height, subsamp, colorspace;
    int res = tjDecompressHeader3(
        jpegDecompressor, data, size, &width, &height, &subsamp, &colorspace);

    if (res != 0) {
        return 1;
    }

    // TODO: this can't possibly be right?
    void *buf = malloc(width * height * 3);
    res = tjDecompress2(
        jpegDecompressor, data, size, reinterpret_cast<unsigned char *>(buf), width, 0, height, TJPF_RGB, 0);

    if (res != 0) {
        return 1;
    }

    free(buf);
    tjDestroy(jpegDecompressor);

    return 0;
}
