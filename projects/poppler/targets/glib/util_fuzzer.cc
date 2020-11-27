#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <poppler.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *tmp_ch;
    char *buf;
    gsize length;
    guint8 *tmp_uint;

    buf = (char *)calloc(size + 1, sizeof(char));
    memcpy(buf, data, size);
    buf[size] = '\0';

    tmp_ch = poppler_named_dest_from_bytestring((const guint8 *)buf, size);
    tmp_uint = poppler_named_dest_to_bytestring(buf, &length);

    g_free(tmp_ch);
    g_free(tmp_uint);
    free(buf);
    return 0;
}
