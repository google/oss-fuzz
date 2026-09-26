// Copyright 2026 Google LLC
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
#include <tree_sitter/api.h>

// Provided by tree-sitter-json
const TSLanguage *tree_sitter_json(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Limit input size to avoid timeouts on pathological inputs
  if (size > 10000) {
    return 0;
  }

  TSParser *parser = ts_parser_new();
  if (!ts_parser_set_language(parser, tree_sitter_json())) {
    ts_parser_delete(parser);
    return 0;
  }

  // Parse the fuzz input as source text
  TSTree *tree = ts_parser_parse_string(parser, NULL, (const char *)data, (uint32_t)size);
  if (tree) {
    // Exercise tree inspection to catch issues in node/tree APIs
    TSNode root = ts_tree_root_node(tree);
    (void)ts_node_child_count(root);
    (void)ts_node_has_error(root);

    // Exercise s-expression serialization
    char *sexp = ts_node_string(root);
    free(sexp);

    ts_tree_delete(tree);
  }

  ts_parser_delete(parser);
  return 0;
}
