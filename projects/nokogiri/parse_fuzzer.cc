// Copyright 2023 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////


#include "nokogiri/gumbo-parser/src/nokogiri_gumbo.h"
#include <stdint.h>

void SanityCheckPointers(
    const char* input, size_t input_length, const GumboNode* node, int depth) {
  if (node->type == GUMBO_NODE_DOCUMENT || depth > 400) {
    return;
  }
  if (node->type == GUMBO_NODE_ELEMENT) {
    const GumboElement* element = &node->v.element;
    const GumboVector* children = &element->children;
    for (unsigned int i = 0; i < children->length; ++i) {
      const GumboNode* child = static_cast<const GumboNode*>(children->data[i]);
      SanityCheckPointers(input, input_length, child, depth + 1);
    }
  } else {
    const GumboText* text = &node->v.text;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 10)
    {
        return 0;
    }
    GumboOptions options = kGumboDefaultOptions;
    GumboOutput* output;
    GumboNode* root;

    output = gumbo_parse_with_options(&options, (char*)data, size);
    root = output->document;
    SanityCheckPointers((char*)data, size, output->root, 0);
    
    if (output) {
      gumbo_destroy_output(output);
    }
    

	return 0;
}