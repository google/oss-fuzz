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
 * Fuzz tree-sitter's query language parser and execution engine.
 *
 * Tree-sitter queries use S-expression patterns to match syntax tree nodes.
 * This is used extensively by editors for syntax highlighting, code folding,
 * textobjects, and more. The query compiler and pattern matcher are complex
 * and parsing arbitrary S-expression patterns is a rich attack surface.
 *
 * The fuzzer splits input into a query pattern and source code, compiles
 * the query, parses the source, and executes the query against the tree.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tree_sitter/api.h"

extern const TSLanguage *tree_sitter_json(void);
extern const TSLanguage *tree_sitter_javascript(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4 || size > 32768)
    return 0;

  /* Use first byte for language selection, second byte for split point */
  uint8_t lang_sel = data[0] % 2;
  uint8_t split_pct = data[1];
  data += 2;
  size -= 2;

  /* Split remaining data into query pattern and source code */
  size_t split = (size * split_pct) / 256;
  if (split < 1)
    split = 1;
  if (split >= size)
    split = size - 1;

  const char *query_src = (const char *)data;
  uint32_t query_len = (uint32_t)split;
  const char *source = (const char *)(data + split);
  uint32_t source_len = (uint32_t)(size - split);

  const TSLanguage *language =
      (lang_sel == 0) ? tree_sitter_json() : tree_sitter_javascript();

  /* Try to compile the query */
  uint32_t error_offset = 0;
  TSQueryError error_type = TSQueryErrorNone;
  TSQuery *query =
      ts_query_new(language, query_src, query_len, &error_offset, &error_type);

  if (!query) {
    /* Invalid query pattern — expected for fuzz input */
    return 0;
  }

  /* Query compiled successfully — exercise the query API */
  (void)ts_query_pattern_count(query);
  (void)ts_query_capture_count(query);
  (void)ts_query_string_count(query);

  uint32_t pattern_count = ts_query_pattern_count(query);
  for (uint32_t i = 0; i < pattern_count && i < 16; i++) {
    (void)ts_query_start_byte_for_pattern(query, i);
    (void)ts_query_is_pattern_rooted(query, i);
    (void)ts_query_is_pattern_non_local(query, i);
  }

  uint32_t capture_count = ts_query_capture_count(query);
  for (uint32_t i = 0; i < capture_count && i < 16; i++) {
    uint32_t length;
    (void)ts_query_capture_name_for_id(query, i, &length);
  }

  /* Parse the source code to get a tree to query against */
  TSParser *parser = ts_parser_new();
  if (!parser) {
    ts_query_delete(query);
    return 0;
  }

  if (!ts_parser_set_language(parser, language)) {
    ts_parser_delete(parser);
    ts_query_delete(query);
    return 0;
  }

  TSTree *tree = ts_parser_parse_string(parser, NULL, source, source_len);

  if (tree) {
    TSNode root = ts_tree_root_node(tree);

    if (!ts_node_is_null(root)) {
      /* Execute the query against the parsed tree */
      TSQueryCursor *cursor = ts_query_cursor_new();
      if (cursor) {
        ts_query_cursor_exec(cursor, query, root);

        /* Consume up to 64 matches */
        TSQueryMatch match;
        uint32_t match_count = 0;
        while (ts_query_cursor_next_match(cursor, &match) &&
               match_count < 64) {
          (void)match.pattern_index;
          for (uint16_t i = 0; i < match.capture_count && i < 16; i++) {
            TSNode node = match.captures[i].node;
            (void)ts_node_type(node);
            (void)ts_node_start_byte(node);
            (void)ts_node_end_byte(node);
          }
          match_count++;
        }

        ts_query_cursor_delete(cursor);
      }
    }

    ts_tree_delete(tree);
  }

  ts_parser_delete(parser);
  ts_query_delete(query);
  return 0;
}
