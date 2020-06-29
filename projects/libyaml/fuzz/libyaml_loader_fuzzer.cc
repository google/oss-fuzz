// Copyright 2020 Google LLC
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

#include "yaml.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef NDEBUG
#undef NDEBUG
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  yaml_parser_t parser;
  yaml_document_t document;
  int done = 0;
  int count = 0;
  int error = 0;

  if(!yaml_parser_initialize(&parser))
    return 0;

  yaml_parser_set_input_string(&parser, data, size);

  while (!done)
  {
      if (!yaml_parser_load(&parser, &document)) {
          error = 1;
          break;
      }

      done = (!yaml_document_get_root_node(&document));

      yaml_document_delete(&document);

      if (!done) count ++;
  }

  yaml_parser_delete(&parser);

  return 0;
}
