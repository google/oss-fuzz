/*
# Copyright 2020 Google Inc.
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
#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "fuzzer_temp_file.h"

#include "libxml.h"
#include "libxml/HTMLparser.h"
#include "libxml/xmlreader.h"


void ignore (void* ctx, const char* msg, ...) {
  // Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSetGenericErrorFunc(NULL, &ignore);

    FuzzedDataProvider provider(data, size);
    const int options = provider.ConsumeIntegral<int>();
    const std::string encoding = provider.ConsumeRandomLengthString(128);
    auto file_contents = provider.ConsumeRemainingBytes<uint8_t>();

    FuzzerTemporaryFile file(file_contents.data(), file_contents.size());

    htmlDocPtr doc = NULL;
    doc = htmlReadFile(file.filename(), encoding.c_str(), options);
    if (doc != NULL)
        xmlFreeDoc(doc);

    return EXIT_SUCCESS;
}
