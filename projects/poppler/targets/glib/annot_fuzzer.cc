#include <stdint.h>
#include <poppler.h>
#include <cairo.h>
#include <cairo-pdf.h>

#include "fuzzer_temp_file.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    GError *err = NULL;
    PopplerDocument *doc;
    PopplerPage *page;
    PopplerAnnot *annot;
    PopplerRectangle bb;
    gdouble width, height;
    gboolean hg;
    int npages;

    cairo_t *cr;
    cairo_surface_t *surface;
    cairo_status_t status;

    doc = poppler_document_new_from_data((char *)data, size, NULL, &err);
    if (doc == NULL) {
        g_error_free(err);
        return 0;
    }
    npages = poppler_document_get_n_pages(doc);
    if (npages < 1) {
        g_object_unref(doc);
        return 0;
    }

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    surface = cairo_pdf_surface_create(tmpfile, 1.0, 1.0);
    status = cairo_surface_status(surface);
    if (status != CAIRO_STATUS_SUCCESS) {
        g_object_unref(doc);
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    for (int n = 0; n < npages; n++) {
        page = poppler_document_get_page(doc, n);
        if (!page) {
            continue;
        }

        poppler_page_get_size(page, &width, &height);
        cairo_pdf_surface_set_size(surface, width, height);
        hg = poppler_page_get_bounding_box(page, &bb);
        if (hg) {
            annot = poppler_annot_text_new(doc, &bb);
            if (annot != NULL) {
                g_object_unref(page);
                continue;
            }
            poppler_page_add_annot(page, annot);
        }

        cr = cairo_create(surface);
        status = cairo_status(cr);
        if (status != CAIRO_STATUS_SUCCESS) {
            cairo_destroy(cr);
            g_object_unref(page);
            continue;
        }
        poppler_page_render_for_printing(page, cr);
        cairo_surface_show_page(surface);
        cairo_destroy(cr);
        g_object_unref(page);
    }
    cairo_surface_destroy(surface);
    fuzzer_release_tmpfile(tmpfile);
    g_object_unref(doc);
    return 0;
}
