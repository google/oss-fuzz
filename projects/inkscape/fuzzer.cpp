#include "inkscape/src/xml/repr.h"
#include "inkscape/src/inkscape.h"
#include "inkscape/src/document.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    g_type_init();
    Inkscape::GC::init();
    if ( !Inkscape::Application::exists() )
        Inkscape::Application::create("", false);
    SPDocument *doc = SPDocument::createNewDocFromMem( (const char*)data, size, 0);
    if(doc)
        doc->doUnref();
    return 0;
}
