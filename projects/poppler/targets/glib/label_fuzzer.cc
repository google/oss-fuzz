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
        page = poppler_document_get_page_by_label(doc, buf);
        if (!page) {
            continue;
        }
        g_object_unref(page);
    }
    free(buf);
    return 0;
}
