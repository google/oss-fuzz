// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdint>
#include <poppler-document.h>
#include <poppler-global.h>
#include <poppler-page.h>
#include <poppler-page-renderer.h>

#include "FuzzedDataProvider.h"

const size_t input_size = 32;

static void dummy_error_function(const std::string &, void *) { }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < input_size) {
        return 0;
    }
    poppler::set_debug_error_function(dummy_error_function, nullptr);

    poppler::document *doc = poppler::document::load_from_raw_data((const char *)data, size);
    if (!doc || doc->is_locked()) {
        delete doc;
        return 0;
    }

    poppler::page_renderer r;
    FuzzedDataProvider data_provider(data, size);
    std::string in_label = data_provider.ConsumeBytesAsString(input_size);
    for (int i = 0; i < doc->pages(); i++) {
        poppler::page *p = doc->create_page(poppler::ustring::from_utf8(in_label.c_str(), -1));
        if (!p) {
            continue;
        }
        r.render_page(p);
        p->label();
        delete p;
    }

    delete doc;
    return 0;
}
