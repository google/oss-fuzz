#include <cstdint>
#include <poppler-destination.h>
#include <poppler-document.h>
#include <poppler-global.h>
#include <poppler-page.h>
#include <poppler-page-renderer.h>

static void dummy_error_function(const std::string &, void *) { }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    poppler::set_debug_error_function(dummy_error_function, nullptr);

    poppler::document *doc = poppler::document::load_from_raw_data((const char *)data, size);
    if (!doc || doc->is_locked()) {
        delete doc;
        return 0;
    }
    doc->metadata();
    doc->create_destination_map();
    doc->embedded_files();
    doc->fonts();

    poppler::page_renderer r;
    for (int i = 0; i < doc->pages(); i++) {
        poppler::page *p = doc->create_page(i);
        if (!p) {
            continue;
        }
        r.render_page(p);
        p->text_list(poppler::page::text_list_include_font);
        delete p;
    }

    delete doc;
    return 0;
}
