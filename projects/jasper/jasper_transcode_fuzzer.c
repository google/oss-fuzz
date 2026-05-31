/*
 * OSS-Fuzz harness for JasPer transcode (decode+encode) path.
 *
 * Uses the first byte as a format hint to explicitly select the
 * input codec, then decodes and transcodes to JPC.  This hits
 * format-specific decoders (JP2 box parser, JPC codestream parser,
 * PGX header parser) with format-appropriate inputs, guided by
 * the fuzzer's mutation of the leading byte.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "jasper/jasper.h"

static const char * const formats[] = {
    "jp2", "jpc", "pgx", "bmp", "ras", "pnm", "jpg", NULL
};
static int num_formats = 0;

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
        /* Count registered formats */
        while (formats[num_formats]) num_formats++;
        initialized = 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || num_formats == 0)
        return 0;

    /* Use the first byte to select the decoder */
    int fmt_idx = data[0] % num_formats;
    int fmtid = jas_image_strtofmt(formats[fmt_idx]);
    if (fmtid < 0)
        goto done;

    jas_stream_t *in = jas_stream_memopen((char *)(data + 1), size - 1);
    if (!in) goto done;

    jas_image_t *image = jas_image_decode(in, fmtid, NULL);
    jas_stream_close(in);

    if (image) {
        /* Transcode to JPC */
        jas_stream_t *out = jas_stream_memopen(NULL, 0);
        if (out) {
            int jpc_id = jas_image_strtofmt("jpc");
            if (jpc_id >= 0)
                jas_image_encode(image, out, jpc_id, NULL);
            jas_stream_close(out);
        }
        jas_image_destroy(image);
    }

done:
    jas_cleanup_thread();
    return 0;
}
