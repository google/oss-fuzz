/*  Copyright 2022 Google Inc.

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
#include <fuzzer/FuzzedDataProvider.h>

#include <vector>
#include <aconf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <png.h>

#include "gmem.h"
#include "gmempp.h"
#include "parseargs.h"
#include "GString.h"
#include "gfile.h"
#include "GlobalParams.h"
#include "Object.h"
#include "PDFDoc.h"
#include "SplashBitmap.h"
#include "Splash.h"
#include "SplashOutputDev.h"
#include "Stream.h"
#include "config.h"

#include "JBIG2Stream.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FuzzedDataProvider fdp(data, size);
  double hdpi = fdp.ConsumeFloatingPoint<double>();
  double vdpi = fdp.ConsumeFloatingPoint<double>();
  int rotate = fdp.ConsumeIntegral<int>();
  bool useMediaBox = fdp.ConsumeBool();
  bool crop = fdp.ConsumeBool();
  bool printing = fdp.ConsumeBool();
  std::vector<char> payload = fdp.ConsumeRemainingBytes<char>();

  Object xpdf_obj;
  xpdf_obj.initNull();
  BaseStream *stream = new MemStream(payload.data(), 0, payload.size(), &xpdf_obj);

  Object info, xfa;
  Object *acroForm;
  globalParams = new GlobalParams(NULL);
  globalParams->setErrQuiet(1);
  globalParams->setupBaseFonts(NULL);
  char yes[] = "yes";
  globalParams->setEnableFreeType(yes); // Yes, it's a string and not a bool.
  globalParams->setErrQuiet(1);

  PDFDoc *doc = NULL;
  try
  {
    PDFDoc doc(stream);
    if (doc.isOk() == gTrue)
    {
      XRef *xref = doc.getXRef();
      int objNums = xref->getNumObjects();
      Object currentObj;
      for (int i = 0; i < objNums; ++i)
      {
        if (xref->fetch(i, 0, &currentObj)->isStream())
        {
          currentObj.getStream()->reset();
        }
      }
      currentObj.free();
    }
  }
  catch (...)
  {
  }

  delete globalParams;

  return 0;
}
