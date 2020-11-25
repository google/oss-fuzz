#include <cairo.h>
#include <cairo-pdf.h>
#include "fuzzer_temp_file.h"

#define WIDTH_IN_INCHES  3
#define HEIGHT_IN_INCHES 3
#define WIDTH_IN_POINTS  (WIDTH_IN_INCHES  * 72.0)
#define HEIGHT_IN_POINTS (HEIGHT_IN_INCHES * 72.0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cairo_t *cr;
    cairo_surface_t *surface;
    cairo_status_t status;
    int flags;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    surface = cairo_pdf_surface_create(tmpfile, WIDTH_IN_POINTS, HEIGHT_IN_POINTS);
    status = cairo_surface_status(surface);
    if (status != CAIRO_STATUS_SUCCESS) {
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    char *buf = (char *) malloc(size + 1);
    memcpy(buf, data, size);
    buf[size] = '\0';

    flags = CAIRO_PDF_OUTLINE_FLAG_BOLD | CAIRO_PDF_OUTLINE_FLAG_OPEN;
    cairo_pdf_surface_set_metadata(surface, CAIRO_PDF_METADATA_TITLE, buf);
    cr = cairo_create(surface);
    cairo_tag_begin(cr, buf, NULL);
    cairo_tag_end(cr, buf);

    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    free(buf);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
