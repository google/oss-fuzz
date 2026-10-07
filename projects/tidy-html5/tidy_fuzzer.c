// Copyright 2018 Google Inc.
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tidy.h"
#include "tidybuffio.h"

void run_tidy_parser(TidyBuffer* data_buffer,
                     TidyBuffer* output_buffer,
                     TidyBuffer* error_buffer) {
    TidyDoc tdoc = tidyCreate();
    if (tidySetErrorBuffer(tdoc, error_buffer) < 0) {
        abort();
    }
    tidyOptSetBool(tdoc, TidyXhtmlOut, yes);
    tidyOptSetBool(tdoc, TidyForceOutput, yes);

    if (tidyParseBuffer(tdoc, data_buffer) >= 0 &&
            tidyCleanAndRepair(tdoc) >= 0 &&
            tidyRunDiagnostics(tdoc) >= 0) {
        tidySaveBuffer(tdoc, output_buffer);
    }
    tidyRelease(tdoc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TidyBuffer data_buffer;
    TidyBuffer output_buffer;
    TidyBuffer error_buffer;
    tidyBufInit(&data_buffer);
    tidyBufInit(&output_buffer);
    tidyBufInit(&error_buffer);

    tidyBufAttach(&data_buffer, (byte*)data, size);
    run_tidy_parser(&data_buffer, &output_buffer, &error_buffer);

    tidyBufFree(&error_buffer);
    tidyBufFree(&output_buffer);
    tidyBufDetach(&data_buffer);
    return 0;
}
