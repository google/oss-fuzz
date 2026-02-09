/* Copyright 2026 Google LLC
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

/*
 * Fuzz tree-sitter's incremental parser with multiple language grammars.
 *
 * Tree-sitter is an incremental parsing system used by many code editors
 * (Neovim, Helix, Zed, GitHub, etc.). This fuzzer exercises the core parser
 * by feeding arbitrary bytes as source code to be parsed with JSON, HTML,
 * and JavaScript grammars, then performs tree operations on the result.
 *
 * Attack surface: the lexer, parser state machine, and tree construction.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tree_sitter/api.h"

/* Language declarations — these are provided by the grammar libraries */
extern const TSLanguage *tree_sitter_json(void);
extern const TSLanguage *tree_sitter_html(void);
extern const TSLanguage *tree_sitter_javascript(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > 65536)
    return 0;

  /* Use the first byte to select the language grammar */
  uint8_t lang_selector = data[0] % 3;
  const char *source = (const char *)(data + 1);
  uint32_t source_len = (uint32_t)(size - 1);

  const TSLanguage *language = NULL;
  switch (lang_selector) {
  case 0:
    language = tree_sitter_json();
    break;
  case 1:
    language = tree_sitter_html();
    break;
  case 2:
    language = tree_sitter_javascript();
    break;
  }

  TSParser *parser = ts_parser_new();
  if (!parser)
    return 0;

  if (!ts_parser_set_language(parser, language)) {
    ts_parser_delete(parser);
    return 0;
  }

  /* Parse the fuzz input as source code */
  TSTree *tree =
      ts_parser_parse_string(parser, NULL, source, source_len);

  if (tree) {
    /* Exercise tree traversal to increase code coverage */
    TSNode root = ts_tree_root_node(tree);

    /* Walk the tree with a cursor */
    if (!ts_node_is_null(root)) {
      (void)ts_node_type(root);
      (void)ts_node_symbol(root);
      (void)ts_node_start_byte(root);
      (void)ts_node_end_byte(root);
      (void)ts_node_child_count(root);
      (void)ts_node_has_error(root);
      (void)ts_node_is_named(root);

      /* Get the S-expression representation */
      char *sexp = ts_node_string(root);
      free(sexp);

      /* Walk children */
      uint32_t child_count = ts_node_child_count(root);
      for (uint32_t i = 0; i < child_count && i < 32; i++) {
        TSNode child = ts_node_child(root, i);
        if (!ts_node_is_null(child)) {
          (void)ts_node_type(child);
          (void)ts_node_is_named(child);
          (void)ts_node_has_error(child);
        }
      }

      /* Exercise tree cursor */
      TSTreeCursor cursor = ts_tree_cursor_new(root);
      int depth = 0;
      bool went_down = true;
      while (depth >= 0 && depth < 100) {
        TSNode node = ts_tree_cursor_current_node(&cursor);
        (void)ts_node_type(node);
        (void)ts_tree_cursor_current_field_name(&cursor);

        if (went_down && ts_tree_cursor_goto_first_child(&cursor)) {
          depth++;
          went_down = true;
        } else if (ts_tree_cursor_goto_next_sibling(&cursor)) {
          went_down = true;
        } else if (ts_tree_cursor_goto_parent(&cursor)) {
          depth--;
          went_down = false;
        } else {
          break;
        }
      }
      ts_tree_cursor_delete(&cursor);
    }

    /* Test incremental parsing: simulate an edit and re-parse */
    if (source_len > 4) {
      TSInputEdit edit = {
          .start_byte = 0,
          .old_end_byte = source_len / 2,
          .new_end_byte = source_len / 2 + 1,
          .start_point = {0, 0},
          .old_end_point = {0, source_len / 2},
          .new_end_point = {0, source_len / 2 + 1},
      };
      ts_tree_edit(tree, &edit);

      TSTree *new_tree =
          ts_parser_parse_string(parser, tree, source, source_len);
      if (new_tree) {
        ts_tree_delete(new_tree);
      }
    }

    ts_tree_delete(tree);
  }

  ts_parser_delete(parser);
  return 0;
}
