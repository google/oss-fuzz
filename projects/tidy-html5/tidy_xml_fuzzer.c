/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "tidy.h"
#include "tidybuffio.h"
#include "tidyenum.h"
#include "tidyplatform.h"

void TidyXml(char *fuzz_inp, TidyBuffer *toutput,
             TidyBuffer *terror) {
  TidyDoc tdoc = tidyCreate();
  tidyBufClear(toutput);
  tidyBufClear(terror);
  if (tidyOptSetBool(tdoc, TidyXmlOut, yes)) {
    tidySetCharEncoding(tdoc, "utf8");
    tidySetErrorBuffer(tdoc, terror);
    tidyOptSetInt(tdoc, TidyWrapLen, 0);
    tidyOptSetBool(tdoc, TidyXmlTags, yes);
    tidyOptSetBool(tdoc, TidyQuoteNbsp, no);
    tidyOptSetBool(tdoc, TidyNumEntities, yes);
    tidyOptSetBool(tdoc, TidyQuiet, yes);
    tidyOptSetBool(tdoc, TidyMark, no);
    tidyOptSetBool(tdoc, TidyShowWarnings, no);
    tidyParseString(tdoc, fuzz_inp);
    tidyCleanAndRepair(tdoc);
    tidyRunDiagnostics(tdoc);
    tidySaveBuffer(tdoc, toutput);
  }

  tidyRelease(tdoc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *fuzz_inp = malloc(size+1);
  memcpy(fuzz_inp, data, size);
  fuzz_inp[size] = '\0';

  TidyBuffer fuzz_toutput;
  TidyBuffer fuzz_terror;

  tidyBufInit(&fuzz_toutput);
  tidyBufInit(&fuzz_terror);

  TidyXml(fuzz_inp, &fuzz_toutput, &fuzz_terror);

  free(fuzz_inp);
  tidyBufFree(&fuzz_toutput);
  tidyBufFree(&fuzz_terror);
  return 0;
}
