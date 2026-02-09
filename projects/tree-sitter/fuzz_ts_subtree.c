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
 * Fuzz tree-sitter's tree editing and incremental re-parsing.
 *
 * This fuzzer tests the incremental parsing path: it parses source code,
 * then applies a series of fuzz-derived edits and re-parses, exercising
 * the tree diffing, node reuse, and subtree invalidation logic. This is
 * one of tree-sitter's most complex and performance-critical code paths.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tree_sitter/api.h"

extern const TSLanguage *tree_sitter_json(void);
extern const TSLanguage *tree_sitter_html(void);

/* Read a uint16 from the fuzz data stream */
static uint16_t read_u16(const uint8_t **p, const uint8_t *end) {
  if (*p + 2 > end)
    return 0;
  uint16_t val = (uint16_t)((*p)[0] | ((*p)[1] << 8));
  *p += 2;
  return val;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 10 || size > 32768)
    return 0;

  /* First byte: language selector; bytes 1-2: source length */
  uint8_t lang_sel = data[0] % 2;
  const uint8_t *cursor = data + 1;
  const uint8_t *end = data + size;

  uint16_t source_len = read_u16(&cursor, end);
  if (source_len == 0 || cursor + source_len > end)
    return 0;

  const char *source = (const char *)cursor;
  cursor += source_len;

  const TSLanguage *language =
      (lang_sel == 0) ? tree_sitter_json() : tree_sitter_html();

  TSParser *parser = ts_parser_new();
  if (!parser)
    return 0;

  if (!ts_parser_set_language(parser, language)) {
    ts_parser_delete(parser);
    return 0;
  }

  /* Initial parse */
  /* Make a mutable copy of the source so we can "edit" it */
  char *buf = (char *)malloc(source_len + 256);
  if (!buf) {
    ts_parser_delete(parser);
    return 0;
  }
  memcpy(buf, source, source_len);
  uint32_t buf_len = source_len;

  TSTree *tree = ts_parser_parse_string(parser, NULL, buf, buf_len);
  if (!tree) {
    free(buf);
    ts_parser_delete(parser);
    return 0;
  }

  /* Apply up to 8 fuzz-driven edits and re-parse each time */
  for (int edit_num = 0; edit_num < 8 && cursor + 6 <= end; edit_num++) {
    uint16_t start = read_u16(&cursor, end);
    uint16_t old_end_off = read_u16(&cursor, end);
    uint16_t insert_len = read_u16(&cursor, end);

    /* Clamp to valid ranges */
    if (start > buf_len)
      start = buf_len;
    uint32_t old_end = start + (old_end_off % (buf_len - start + 1));
    if (insert_len > 64)
      insert_len = 64;
    if (insert_len > (uint16_t)(end - cursor))
      insert_len = (uint16_t)(end - cursor);

    /* Tell tree-sitter about the edit */
    TSInputEdit edit = {
        .start_byte = start,
        .old_end_byte = old_end,
        .new_end_byte = start + insert_len,
        .start_point = {0, start},
        .old_end_point = {0, old_end},
        .new_end_point = {0, start + insert_len},
    };
    ts_tree_edit(tree, &edit);

    /* Apply the edit to our buffer:
     * Delete bytes [start, old_end), insert insert_len bytes from fuzz data */
    uint32_t del_count = old_end - start;
    uint32_t new_len = buf_len - del_count + insert_len;
    if (new_len > source_len + 256) {
      /* Don't overflow our buffer */
      break;
    }

    memmove(buf + start + insert_len, buf + old_end, buf_len - old_end);
    if (insert_len > 0 && cursor + insert_len <= end) {
      memcpy(buf + start, cursor, insert_len);
      cursor += insert_len;
    }
    buf_len = new_len;

    /* Re-parse with the old tree for incremental parsing */
    TSTree *new_tree = ts_parser_parse_string(parser, tree, buf, buf_len);
    if (new_tree) {
      /* Get changed ranges between old and new trees */
      uint32_t range_count = 0;
      TSRange *ranges =
          ts_tree_get_changed_ranges(tree, new_tree, &range_count);
      free(ranges);

      /* Walk the new tree briefly */
      TSNode root = ts_tree_root_node(new_tree);
      if (!ts_node_is_null(root)) {
        (void)ts_node_has_error(root);
        (void)ts_node_child_count(root);
        (void)ts_node_descendant_count(root);
      }

      ts_tree_delete(tree);
      tree = new_tree;
    } else {
      break;
    }
  }

  ts_tree_delete(tree);
  free(buf);
  ts_parser_delete(parser);
  return 0;
}
