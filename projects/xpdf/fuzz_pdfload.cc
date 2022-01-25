/*  Copyright 2020 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <exception>
#include <cstddef>
#include "PDFDoc.h"
#include "GlobalParams.h"
#include "Zoox.h"
#include "TextOutputDev.h"
#include "Stream.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size) {
  try {
        Object xpdf_obj;
        xpdf_obj.initNull();
        BaseStream *stream = new MemStream(const_cast<char *>(reinterpret_cast<const char *>(Data)), 0, Size, &xpdf_obj);
        /*  The following code has in memory-leaks :/ */
        globalParams = new GlobalParams(NULL);
        globalParams->setErrQuiet(gTrue);

        PDFDoc doc(stream);
        if (!doc.isOk()) {
          return 0;
        }

        doc.getOutline();
        doc.getStructTreeRoot();
        doc.getXRef();
        doc.readMetadata();
        Object info;
        doc.getDocInfo(&info);
        if (info.isDict()) {
          info.getDict();
        }
        info.free();

        for (size_t i = 0; i < doc.getNumPages(); i++) {
          doc.getLinks(i);
          auto page = doc.getCatalog()->getPage(i);
          if (!page->isOk()) {
            continue;
          }
          page->getResourceDict();
          page->getMetadata();
          page->getResourceDict();
        }


        auto textOut = new TextOutputDev(NULL,
                                         /*physLayout*/ gFalse, /*fixedPitch*/ gFalse,
                                         /*rawOrder*/ gFalse);

        delete textOut;
        delete globalParams;
    } catch (...) {

    }
        
  return 0;
}
