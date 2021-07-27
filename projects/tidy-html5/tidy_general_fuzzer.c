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

// All boolean options. These will be set randomly
// based on the fuzzer data.
TidyOptionId bool_options[] = {
  TidyJoinClasses, 
  TidyJoinStyles, 
  TidyKeepFileTimes, 
  TidyKeepTabs, 
  TidyLiteralAttribs, 
  TidyLogicalEmphasis, 
  TidyLowerLiterals, 
  TidyMakeBare, 
  TidyFixUri, 
  TidyForceOutput, 
  TidyGDocClean, 
  TidyHideComments,
  TidyMark, 
  TidyXmlTags, 
  TidyMakeClean,
  TidyAnchorAsName, 
  TidyMergeEmphasis, 
  TidyMakeBare, 
  TidyMetaCharset, 
  TidyMuteShow, 
  TidyNCR, 
  TidyNumEntities, 
  TidyOmitOptionalTags, 
  TidyPunctWrap, 
  TidyQuiet,
  TidyQuoteAmpersand,  
  TidyQuoteMarks, 
  TidyQuoteNbsp, 
  TidyReplaceColor, 
  TidyShowFilename, 
  TidyShowInfo, 
  TidyShowMarkup, 
  TidyShowMetaChange, 
  TidyShowWarnings, 
  TidySkipNested, 
  TidyUpperCaseTags, 
  TidyWarnPropAttrs, 
  TidyWord2000, 
  TidyWrapAsp, 
  TidyWrapAttVals, 
  TidyWrapJste, 
  TidyWrapPhp, 
  TidyWrapScriptlets, 
  TidyWrapSection, 
  TidyWriteBack,
};

void set_option(const uint8_t** data, size_t *size, TidyDoc *tdoc, TidyOptionId tboolID) {
  uint8_t decider;
  decider = **data;
  *data += 1; 
  *size -= 1;
  if (decider % 2 == 0) tidyOptSetBool( *tdoc, tboolID, yes );
  else { tidyOptSetBool( *tdoc, tboolID, no ); }
}

int TidyXhtml(const uint8_t* data, size_t size, TidyBuffer* output, TidyBuffer* errbuf) {
  uint8_t decider;

  // We need enough data for picking all of the options. One byte per option.
  if (size < 5+(sizeof(bool_options)/sizeof(bool_options[0]))) {
    return 0;
  }

  TidyDoc tdoc = tidyCreate();

  // Decide output format
  decider = *data;
  data++; size--;
  if (decider % 3 == 0) tidyOptSetBool( tdoc, TidyXhtmlOut, yes );
  else { tidyOptSetBool( tdoc, TidyXhtmlOut, no ); }

  if (decider % 3 == 1) tidyOptSetBool( tdoc, TidyHtmlOut, yes );
  else { tidyOptSetBool( tdoc, TidyHtmlOut, no ); }

  if (decider % 3 == 2) tidyOptSetBool( tdoc, TidyXmlOut, yes );
  else { tidyOptSetBool( tdoc, TidyXmlOut, no ); }

  // Set options 
  for (int i=0; i < sizeof(bool_options)/sizeof(TidyOptionId); i++) {
    set_option(&data, &size, &tdoc, bool_options[i]);
  }

  // Set an error buffer.
  tidySetErrorBuffer(tdoc, errbuf);

  // Parse the data
  decider = *data;
  data++; size--;
  switch (decider % 2) {
    case 0: {
      char filename[256];
      sprintf(filename, "/tmp/libfuzzer.%d", getpid());

      FILE *fp = fopen(filename, "wb");
      if (!fp) {
          return 0;
      }
      fwrite(data, size, 1, fp);
      fclose(fp);

      tidyParseFile(tdoc, filename);
      unlink(filename);
    }
    break;
    case 1: {
      char *inp = malloc(size+1);
      inp[size] = '\0';
      memcpy(inp, data, size);
      tidyParseString(tdoc, inp);
      free(inp);
    }
  }

  // Cleanup
  tidyRelease( tdoc );

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
