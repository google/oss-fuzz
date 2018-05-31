/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <cstdint>

#include <poppler-global.h>
#include <poppler-document.h>
#include <poppler-page.h>
#include <poppler-page-renderer.h>

static void nop_func(const std::string& msg, void*) {};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  poppler::set_debug_error_function(nop_func, nullptr);

  poppler::document *doc = poppler::document::load_from_raw_data((const char *)data, size);
  if (!doc || doc->is_locked()) {
    delete doc;
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
  return 0;
}
