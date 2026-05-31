/*
 * OSS-Fuzz harness for JasPer image encode path.
 *
 * Decodes arbitrary input as any supported format, then re-encodes
 * the resulting image to JPEG-2000 (JPC) and BMP.  Exercises the
 * encode path and the internal image-manipulation APIs.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "jasper/jasper.h"

static int initialized = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    if (!initialized) {
        jas_conf_clear();
        jas_conf_set_max_mem_usage(256 * 1024 * 1024);
        jas_conf_set_debug_level(0);
        if (jas_init_library() != 0) return -1;
        if (jas_init_thread() != 0) return -1;
        initialized = 1;
    }
    return 0;
}

static void encode_to_format(jas_image_t *image, const char *fmtname)
{
    jas_stream_t *out = jas_stream_memopen(NULL, 0);
    if (!out) return;

    int fmtid = jas_image_strtofmt(fmtname);
    if (fmtid >= 0)
        jas_image_encode(image, out, fmtid, NULL);

    jas_stream_close(out);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4)
        return 0;

    jas_stream_t *in = jas_stream_memopen((char *)data, size);
    if (!in) return 0;

    jas_image_t *image = jas_image_decode(in, -1, NULL);
    jas_stream_close(in);

    if (image) {
        /* Encode to multiple formats to exercise different codecs */
        encode_to_format(image, "jpc");
        encode_to_format(image, "bmp");
        encode_to_format(image, "pgx");
        jas_image_destroy(image);
    }

    jas_cleanup_thread();
    return 0;
}
