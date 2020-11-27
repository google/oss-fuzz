#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <poppler.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    GError *err = NULL;
    PopplerDocument *doc;
    PopplerPage *page;
    char *buf;
    int npages;

    doc = poppler_document_new_from_data((char *)data, size, NULL, &err);
    if (doc == NULL) {
        g_error_free(err);
        return 0;
    }

    npages = poppler_document_get_n_pages(doc);
    if (npages < 1) {
        return 0;
    }

    buf = (char *)calloc(size + 1, sizeof(char));
    memcpy(buf, data, size);
    buf[size] = '\0';

    for (int n = 0; n < npages; n++) {
        page = poppler_document_get_page(doc, n);
        if (!page) {
            continue;
        }
        poppler_page_find_text(page, buf);
        g_object_unref(page);
    }
    free(buf);
    return 0;
}
