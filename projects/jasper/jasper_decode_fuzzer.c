/*
 * OSS-Fuzz harness for JasPer image decode path.
 *
 * Fuzzes jas_image_decode() across all registered image formats
 * (JPEG-2000/JPC, JP2, PGX, BMP, RAS, PPM, etc.) by presenting
 * arbitrary byte sequences as in-memory streams.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jasper/jasper.h"

static int initialized = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    if (!initialized) {
        jas_conf_clear();
        jas_conf_set_max_mem_usage(256 * 1024 * 1024); /* 256 MB */
        jas_conf_set_debug_level(0);
        if (jas_init_library() != 0)
            return -1;
        if (jas_init_thread() != 0)
            return -1;
        initialized = 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    jas_stream_t *stream = jas_stream_memopen((char *)data, size);
    if (!stream)
        return 0;

    /* Let JasPer auto-detect the format (-1 = auto) */
    jas_image_t *image = jas_image_decode(stream, -1, NULL);
    jas_stream_close(stream);

    if (image) {
        /* Exercise metadata accessors on the decoded image */
        (void)jas_image_numcmpts(image);
        (void)jas_image_width(image);
        (void)jas_image_height(image);
        (void)jas_image_clrspc(image);
        jas_image_destroy(image);
    }

    jas_cleanup_thread();
    return 0;
}
