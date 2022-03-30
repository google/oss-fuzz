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
#include "yaml_write_handler.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef NDEBUG
#undef NDEBUG
#endif

#define MAX_DOCUMENTS 16

bool nodes_equal(yaml_document_t *document1, int index1,
                 yaml_document_t *document2, int index2, int level) {
  const bool equal = true;

  if (level++ > 1000)
    return !equal;
  yaml_node_t *node1 = yaml_document_get_node(document1, index1);

  if (!node1)
    return !equal;

  yaml_node_t *node2 = yaml_document_get_node(document2, index2);

  if (!node2)
    return !equal;

  if (node1->type != node2->type)
    return !equal;

  if (strcmp((char *)node1->tag, (char *)node2->tag) != 0)
    return !equal;

  switch (node1->type) {
  case YAML_SCALAR_NODE:
    if (node1->data.scalar.length != node2->data.scalar.length)
      return !equal;
    if (strncmp((char *)node1->data.scalar.value,
                (char *)node2->data.scalar.value,
                node1->data.scalar.length) != 0)
      return !equal;
    break;
  case YAML_SEQUENCE_NODE:
    if ((node1->data.sequence.items.top - node1->data.sequence.items.start) !=
        (node2->data.sequence.items.top - node2->data.sequence.items.start))
      return !equal;
    for (int k = 0; k < (node1->data.sequence.items.top -
                         node1->data.sequence.items.start);
         k++) {
      if (!nodes_equal(document1, node1->data.sequence.items.start[k],
                       document2, node2->data.sequence.items.start[k], level))
        return !equal;
    }
    break;
  case YAML_MAPPING_NODE:
    if ((node1->data.mapping.pairs.top - node1->data.mapping.pairs.start) !=
        (node2->data.mapping.pairs.top - node2->data.mapping.pairs.start))
      return !equal;
    for (int k = 0;
         k < (node1->data.mapping.pairs.top - node1->data.mapping.pairs.start);
         k++) {
      if (!nodes_equal(document1, node1->data.mapping.pairs.start[k].key,
                       document2, node2->data.mapping.pairs.start[k].key,
                       level))
        return !equal;
      if (!nodes_equal(document1, node1->data.mapping.pairs.start[k].value,
                       document2, node2->data.mapping.pairs.start[k].value,
                       level))
        return !equal;
    }
    break;
  default:
    return !equal;
  }
  return equal;
}

bool documents_equal(yaml_document_t *document1, yaml_document_t *document2) {

  const bool equal = true;

  if ((document1->version_directive && !document2->version_directive) ||
      (!document1->version_directive && document2->version_directive) ||
      (document1->version_directive && document2->version_directive &&
       (document1->version_directive->major !=
            document2->version_directive->major ||
        document1->version_directive->minor !=
            document2->version_directive->minor)))
    return !equal;

  if ((document1->tag_directives.end - document1->tag_directives.start) !=
      (document2->tag_directives.end - document2->tag_directives.start))
    return !equal;
  for (int k = 0;
       k < (document1->tag_directives.end - document1->tag_directives.start);
       k++) {
    if ((strcmp((char *)document1->tag_directives.start[k].handle,
                (char *)document2->tag_directives.start[k].handle) != 0) ||
        (strcmp((char *)document1->tag_directives.start[k].prefix,
                (char *)document2->tag_directives.start[k].prefix) != 0))
      return !equal;
  }

  if ((document1->nodes.top - document1->nodes.start) !=
      (document2->nodes.top - document2->nodes.start))
    return !equal;

  if (document1->nodes.top != document1->nodes.start) {
    if (!nodes_equal(document1, 1, document2, 1, 0))
      return !equal;
  }

  return equal;
}

bool copy_document(yaml_document_t *document_to,
                   yaml_document_t *document_from) {
  bool error = true;

  yaml_node_t *node;
  yaml_node_item_t *item;
  yaml_node_pair_t *pair;

  if (!yaml_document_initialize(document_to, document_from->version_directive,
                                document_from->tag_directives.start,
                                document_from->tag_directives.end,
                                document_from->start_implicit,
                                document_from->end_implicit))
    return !error;

  for (node = document_from->nodes.start; node < document_from->nodes.top;
       node++) {
    switch (node->type) {
    case YAML_SCALAR_NODE:
      if (!yaml_document_add_scalar(
              document_to, node->tag, node->data.scalar.value,
              node->data.scalar.length, node->data.scalar.style))
        goto out;
      break;
    case YAML_SEQUENCE_NODE:
      if (!yaml_document_add_sequence(document_to, node->tag,
                                      node->data.sequence.style))
        goto out;
      break;
    case YAML_MAPPING_NODE:
      if (!yaml_document_add_mapping(document_to, node->tag,
                                     node->data.mapping.style))
        goto out;
      break;
    default:
      goto out;
    }
  }

  for (node = document_from->nodes.start; node < document_from->nodes.top;
       node++) {
    switch (node->type) {
    case YAML_SEQUENCE_NODE:
      for (item = node->data.sequence.items.start;
           item < node->data.sequence.items.top; item++) {
        if (!yaml_document_append_sequence_item(
                document_to, node - document_from->nodes.start + 1, *item))
          goto out;
      }
      break;
    case YAML_MAPPING_NODE:
      for (pair = node->data.mapping.pairs.start;
           pair < node->data.mapping.pairs.top; pair++) {
        if (!yaml_document_append_mapping_pair(
                document_to, node - document_from->nodes.start + 1, pair->key,
                pair->value))
          goto out;
      }
      break;
    default:
      break;
    }
  }
  return error;

out:
  yaml_document_delete(document_to);
  return !error;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return 0;

  yaml_parser_t parser;
  yaml_emitter_t emitter;

  yaml_document_t document;
  yaml_document_t documents[MAX_DOCUMENTS];
  size_t document_number = 0;
  int count = 0;
  bool done = false;
  bool equal = false;
  bool is_canonical = data[0] & 1;
  bool is_unicode = data[1] & 1;
  data += 2;
  size -= 2;

  if (!yaml_parser_initialize(&parser))
    return 0;

  yaml_parser_set_input_string(&parser, data, size);
  if (!yaml_emitter_initialize(&emitter))
    return 0;

  yaml_emitter_set_canonical(&emitter, is_canonical);
  yaml_emitter_set_unicode(&emitter, is_unicode);

  yaml_output_buffer_t out = {/*buf=*/NULL, /*size=*/0};
  yaml_emitter_set_output(&emitter, yaml_write_handler, &out);
  yaml_emitter_open(&emitter);

  while (!done) {
    if (!yaml_parser_load(&parser, &document)) {
      equal = 1;
      break;
    }

    done = (!yaml_document_get_root_node(&document));
    if (!done) {
      if (document_number >= MAX_DOCUMENTS) {
        yaml_document_delete(&document);
        equal = true;
        break;
      }

      if (!copy_document(&documents[document_number++], &document)) {
        yaml_document_delete(&document);
        equal = true;
        break;
      }
      if (!(yaml_emitter_dump(&emitter, &document) ||
            (yaml_emitter_flush(&emitter) && 0))) {
        equal = true;
        break;
      }

      count++;
    } else {
      yaml_document_delete(&document);
    }
  }

  yaml_parser_delete(&parser);
  yaml_emitter_close(&emitter);
  yaml_emitter_delete(&emitter);

  if (!equal) {
    count = 0;
    done = false;
    if (!yaml_parser_initialize(&parser))
      goto error;

    if (!out.buf) {
      yaml_parser_delete(&parser);
      goto error;
    }

    yaml_parser_set_input_string(&parser, out.buf, out.size);

    while (!done) {
      if (!yaml_parser_load(&parser, &document)) {
        yaml_parser_delete(&parser);
        goto error;
      }

      done = (!yaml_document_get_root_node(&document));
      if (!done) {
        if (!documents_equal(documents + count, &document)) {
          yaml_parser_delete(&parser);
          goto error;
        }
        count++;
      }
      yaml_document_delete(&document);
    }
    yaml_parser_delete(&parser);
  }

  for (int k = 0; k < document_number; k++) {
    yaml_document_delete(documents + k);
  }

error:

  free(out.buf);
  return 0;
}
