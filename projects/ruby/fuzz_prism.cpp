/* Copyright 2025 Google LLC
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

/*
 * Fuzzer for Ruby's Prism compiler (prism_compile.c)
 * Tests parsing of Ruby source code using the Prism parser API directly
 * to find bugs in Ruby's cutting-edge parser implementation.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "prism.h"
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) {
        return 0;
    }
    
    // Initialize parser with default options
    pm_options_t options = {0};
    pm_options_frozen_string_literal_set(&options, false);
    
    pm_parser_t parser;
    pm_parser_init(&parser, data, size, &options);
    
    // Parse the input
    pm_node_t *node = pm_parse(&parser);
    
    // Clean up
    if (node) {
        pm_node_destroy(&parser, node);
    }
    pm_parser_free(&parser);
    pm_options_free(&options);
    
    return 0;
}
