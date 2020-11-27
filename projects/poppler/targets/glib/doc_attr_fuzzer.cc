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
    int npages, n;

    doc = poppler_document_new_from_data((char *)data, size, NULL, &err);
    if (doc == NULL) {
        g_error_free(err);
        return 0;
    }

    buf = (char *)calloc(size + 1, sizeof(char));
    memcpy(buf, data, size);
    buf[size] = '\0';

    poppler_document_set_author(doc, buf);
    poppler_document_set_creator(doc, buf);
    poppler_document_set_keywords(doc, buf);
    poppler_document_set_producer(doc, buf);
    poppler_document_set_subject(doc, buf);
    poppler_document_set_title(doc, buf);

    free(buf);
    return 0;
}
