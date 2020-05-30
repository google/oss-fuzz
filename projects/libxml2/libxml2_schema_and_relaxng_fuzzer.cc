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
#include <cassert>
#include <cstddef>
#include <cstdint>

#include <functional>
#include <limits>
#include <string>

#include "libxml/xmlmemory.h"
#include "libxml/parser.h"
#include "libxml/relaxng.h"

// We keep this schema here for performance reasons.
// This is the schema that we will validate our fuzz data against.
// We do not want the following data to be given by the fuzzer, as 
// that would make us fuzz parts of the code we already do in other
// fuzzers.
static char schema_buf_1[] =
"<?xml version=\"1.0\"?>\n\
<element name=\"foo\"\n\
         xmlns=\"http://relaxng.org/ns/structure/1.0\"\n\
         xmlns:a=\"http://relaxng.org/ns/annotation/1.0\"\n\
         xmlns:ex1=\"http://www.example.com/n1\"\n\
         xmlns:ex2=\"http://www.example.com/n2\">\n\
  <a:documentation>A foo element.</a:documentation>\n\
  <element name=\"ex1:bar1\">\n\
    <empty/>\n\
  </element>\n\
  <element name=\"ex2:bar2\">\n\
    <empty/>\n\
  </element>\n\
</element>\n";

void ignore (void* ctx, const char* msg, ...) {
    // Error handler to avoid spam of error messages from libxml parser.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSetGenericErrorFunc(NULL, &ignore);

    // Test default empty options value and some random combination.
    std::string data_string(reinterpret_cast<const char*>(data), size);
    const std::size_t data_hash = std::hash<std::string>()(data_string);
    const int max_option_value = std::numeric_limits<int>::max();
    int random_option_value = data_hash % max_option_value;

    // Disable XML_PARSE_HUGE to avoid stack overflow.
    random_option_value &= ~XML_PARSE_HUGE;
    const int options[] = {0, random_option_value};

    for (const auto option_value : options) 
    {
        // Intentionally pass raw data as the API does not require trailing \0.
        // Also, skip the first character of the data since we will use the first byte 
        // to determine which of our two schemas we will match against.
        if (auto doc = xmlReadMemory(reinterpret_cast<const char*>(data), size,
                                     "noname.xml", NULL, option_value)) {
            xmlRelaxNGPtr schema = NULL;
            xmlRelaxNGParserCtxtPtr parser_ctxt;
            xmlRelaxNGValidCtxtPtr valid_ctxt;

            parser_ctxt = xmlRelaxNGNewMemParserCtxt(
                                    (char *)schema_buf_1,sizeof(schema_buf_1));
            schema = xmlRelaxNGParse(parser_ctxt);
            if (schema != NULL)
            {
                valid_ctxt = xmlRelaxNGNewValidCtxt(schema);
                xmlRelaxNGValidateDoc(valid_ctxt, doc);
                xmlRelaxNGFreeValidCtxt(valid_ctxt);
                xmlRelaxNGFree(schema);
            }
            xmlRelaxNGFreeParserCtxt(parser_ctxt);
            xmlFreeDoc(doc);
        }
    }
    return 0;
}
