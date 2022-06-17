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
#include <unistd.h>
#include "tidybuffio.h"
#include "tidy.h"


int TidyXhtml(const uint8_t* data, size_t size, TidyBuffer* output, TidyBuffer* errbuf) {
  Bool ok;

  TidyDoc tdoc = tidyCreate();

  ok = tidyOptSetBool( tdoc, TidyXhtmlOut, yes );
  if (ok) tidySetErrorBuffer(tdoc, errbuf);
 
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  tidyParseFile(tdoc, filename);

  tidyRelease( tdoc );
  unlink(filename);

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  TidyBuffer fuzz_toutput;
  TidyBuffer fuzz_terror;

  tidyBufInit(&fuzz_toutput);
  tidyBufInit(&fuzz_terror);

  TidyXhtml(data, size, &fuzz_toutput, &fuzz_terror);

  tidyBufFree(&fuzz_toutput);
  tidyBufFree(&fuzz_terror);
  return 0;
}

