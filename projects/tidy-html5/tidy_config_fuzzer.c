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

#include "fuzzer_temp_file.h"
#include "tidy.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TidyDoc tdoc = tidyCreate();

    // At the time this fuzzer was written, the configuration parser could
    // only be exercised via a file interface.
    char* tmpfile = fuzzer_get_tmpfile(data, size);
    tidyLoadConfig(tdoc, tmpfile);
    fuzzer_release_tmpfile(tmpfile);
    tidyRelease(tdoc);
    return 0;
}
