/*
 * OSS-Fuzz harness for CUPS IPP (Internet Printing Protocol) message parser.
 *
 * Exercises ippReadIO() which parses binary IPP messages from arbitrary input.
 * IPP messages are used in all CUPS print job submissions, attribute queries,
 * and administrative operations.
 */
#include <cups/cups.h>
#include <cups/ipp.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    const uint8_t *data;
    size_t         size;
    size_t         pos;
} fuzz_buffer_t;

static ssize_t fuzz_read(void *ctx, ipp_uchar_t *buf, size_t nbytes) {
    fuzz_buffer_t *fb = (fuzz_buffer_t *)ctx;
    size_t avail = fb->size - fb->pos;
    if (avail == 0) return -1;
    size_t n = avail < nbytes ? avail : nbytes;
    memcpy(buf, fb->data + fb->pos, n);
    fb->pos += n;
    return (ssize_t)n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_buffer_t fb = { data, size, 0 };
    ipp_t *ipp = ippNew();
    if (!ipp) return 0;

    /* Parse the fuzzer-provided bytes as an IPP message */
    ippReadIO(&fb, (ipp_iocb_t)fuzz_read, 1, NULL, ipp);

    /* Walk all attributes to exercise the accessor paths */
    ipp_attribute_t *attr = ippFirstAttribute(ipp);
    while (attr) {
        ippGetName(attr);
        ippGetValueTag(attr);
        int count = ippGetCount(attr);
        for (int i = 0; i < count; i++) {
            switch (ippGetValueTag(attr)) {
                case IPP_TAG_INTEGER:
                case IPP_TAG_ENUM:
                    ippGetInteger(attr, i);
                    break;
                case IPP_TAG_STRING:
                case IPP_TAG_TEXT:
                case IPP_TAG_NAME:
                case IPP_TAG_URI:
                case IPP_TAG_KEYWORD:
                    ippGetString(attr, i, NULL);
                    break;
                case IPP_TAG_BOOLEAN:
                    ippGetBoolean(attr, i);
                    break;
                default:
                    break;
            }
        }
        attr = ippNextAttribute(ipp);
    }

    ippDelete(ipp);
    return 0;
}
