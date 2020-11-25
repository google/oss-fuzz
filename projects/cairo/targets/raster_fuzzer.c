#include <cairo.h>
#include <cairo-pdf.h>
#include "fuzzer_temp_file.h"

#define WIDTH 200
#define HEIGHT 80

static cairo_surface_t *
acquire (cairo_pattern_t *pattern, void *closure,
	     cairo_surface_t *target,
	     const cairo_rectangle_int_t *extents)
{
    return cairo_image_surface_create_from_png(closure);
}

static void
release (cairo_pattern_t *pattern, void *closure, cairo_surface_t *surface)
{
    cairo_surface_destroy(surface);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cairo_t *cr;
    cairo_surface_t *surface;
    cairo_pattern_t *pattern;
    cairo_content_t content;
    cairo_status_t status;
    int w, h;

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    surface = cairo_image_surface_create_from_png(tmpfile);
    status = cairo_surface_status (surface);
    if (status != CAIRO_STATUS_SUCCESS) {
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    cr = cairo_create(surface);
    content = cairo_surface_get_content(surface);
    w = cairo_image_surface_get_width(surface);
    h = cairo_image_surface_get_height(surface);

    char *buf = (char *) malloc(size + 1);
    memcpy(buf, data, size);
    buf[size] = '\0';

    pattern = cairo_pattern_create_raster_source(buf, content, w, h);
    cairo_raster_source_pattern_set_acquire (pattern, acquire, release);
    cairo_set_source(cr, pattern);
    cairo_pdf_surface_set_page_label(surface, buf);
    cairo_pdf_surface_set_metadata(surface, CAIRO_PDF_METADATA_KEYWORDS, buf);
    cairo_paint(cr);

    cairo_destroy(cr);
    cairo_pattern_destroy(pattern);
    cairo_surface_destroy(surface);
    free(buf);
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
