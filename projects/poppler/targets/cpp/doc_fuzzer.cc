#include <cstdint>
#include <poppler-document.h>
#include <poppler-global.h>

#include "FuzzedDataProvider.h"

const size_t input_size = 32;
const size_t count = 6;

static void dummy_error_function(const std::string &, void *) { }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < input_size * count) {
        return 0;
    }
    poppler::set_debug_error_function(dummy_error_function, nullptr);
    poppler::document *doc = poppler::document::load_from_raw_data((const char *)data, size);
    if (!doc || doc->is_locked()) {
        delete doc;
        return 0;
    }

    FuzzedDataProvider data_provider(data, size);
    std::string in_auth = data_provider.ConsumeBytesAsString(input_size);
    std::string in_creat = data_provider.ConsumeBytesAsString(input_size);
    std::string in_key = data_provider.ConsumeBytesAsString(input_size);
    std::string in_prod = data_provider.ConsumeBytesAsString(input_size);
    std::string in_sub = data_provider.ConsumeBytesAsString(input_size);
    std::string in_title = data_provider.ConsumeBytesAsString(input_size);

    // Testing both methods for conversion to ustring
    doc->set_author(poppler::ustring::from_latin1(in_auth));
    doc->set_creator(poppler::ustring::from_latin1(in_creat));
    doc->set_keywords(poppler::ustring::from_latin1(in_key));
    doc->set_producer(poppler::ustring::from_latin1(in_prod));
    doc->set_subject(poppler::ustring::from_latin1(in_sub));
    doc->set_title(poppler::ustring::from_latin1(in_title));

    doc->set_author(poppler::ustring::from_utf8(in_auth.c_str(), -1));
    doc->set_creator(poppler::ustring::from_utf8(in_creat.c_str(), -1));
    doc->set_keywords(poppler::ustring::from_utf8(in_key.c_str(), -1));
    doc->set_producer(poppler::ustring::from_utf8(in_prod.c_str(), -1));
    doc->set_subject(poppler::ustring::from_utf8(in_sub.c_str(), -1));
    doc->set_title(poppler::ustring::from_utf8(in_title.c_str(), -1));

    delete doc;
    return 0;
}
