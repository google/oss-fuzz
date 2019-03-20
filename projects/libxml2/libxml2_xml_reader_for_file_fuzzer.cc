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

#include <cstddef>
#include <cstdint>
#include <string>

#include "byte_stream.h"
#include "fuzzer_temp_file.h"

#include "libxml/xmlreader.h"

void ignore (void* ctx, const char* msg, ...) {
  // Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  xmlSetGenericErrorFunc(NULL, &ignore);

  ByteStream stream(data, size);
  const int options = stream.GetNextInt();
  const std::string encoding = stream.GetNextString();
  size_t file_contents_size = 0;
  const uint8_t* file_contents = stream.GetNextChunk(&file_contents_size);

  // Intentionally pass raw data as the API does not require trailing \0.
  FuzzerTemporaryFile file(file_contents, file_contents_size);

  xmlTextReaderPtr xmlReader =
      xmlReaderForFile(file.filename(), encoding.c_str(), options);

  constexpr int kReadSuccessful = 1;
  while (xmlTextReaderRead(xmlReader) == kReadSuccessful) {
    xmlTextReaderNodeType(xmlReader);
    xmlTextReaderConstValue(xmlReader);
  }

  xmlFreeTextReader(xmlReader);
  return EXIT_SUCCESS;
}
