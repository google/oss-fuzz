#include "cpp/poppler-document.h"
#include "cpp/poppler-global.h"
#include "cpp/poppler-image.h"
#include "cpp/poppler-page-renderer.h"
#include "cpp/poppler-page.h"

using namespace poppler;

static void empty_function(const std::string& msg, void*) {};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // otherwise poppler is very chatty
  set_debug_error_function(empty_function, nullptr);

  page_renderer pr;
  if (!pr.can_render())
    return 0;

  std::unique_ptr<document> doc(
      document::load_from_raw_data(reinterpret_cast<const char*>(data), size));
  if (!doc.get())
    return 0;

  // antialiasing (1), text_antialiasing (2), text_hinting (4)
  pr.set_render_hints(size & 7);

  for (int i = 0; i < doc->pages(); i++) {
    std::unique_ptr<page> p(doc->create_page(i));
    if (!p.get())
      continue;
    image img = pr.render_page(p.get());
    if (!img.is_valid())
      continue;
  }

  return 0;
}
