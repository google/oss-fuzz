#include <cstdint>
#include <poppler-document.h>
#include <poppler-global.h>
#include <poppler-page.h>
#include <poppler-page-renderer.h>

#include "fuzzer_temp_file.h"

static void dummy_error_function(const std::string &, void *) { }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    poppler::set_debug_error_function(dummy_error_function, nullptr);

    char *tmpfile = fuzzer_get_tmpfile(data, size);
    std::string fname(tmpfile);
    poppler::document *doc = poppler::document::load_from_file(fname);
    if (!doc || doc->is_locked()) {
        delete doc;
        fuzzer_release_tmpfile(tmpfile);
        return 0;
    }

    poppler::page_renderer r;
    for (int i = 0; i < doc->pages(); i++) {
        poppler::page *p = doc->create_page(i);
        if (!p) {
            continue;
        }
        r.render_page(p);
        delete p;
    }

    delete doc;
    fuzzer_release_tmpfile(tmpfile);
    return 0;
}
