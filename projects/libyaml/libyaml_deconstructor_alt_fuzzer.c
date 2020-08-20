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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return 0;

  bool done = false;
  bool is_canonical = data[0] & 1;
  bool is_unicode = data[1] & 1;
  data += 2;
  size -= 2;

  yaml_parser_t parser;
  yaml_emitter_t emitter;
  yaml_event_t input_event;
  yaml_document_t output_document;

  int root;

  /* Initialize the parser and emitter objects. */

  if (!yaml_parser_initialize(&parser)) {
    return 1;
  }

  if (!yaml_emitter_initialize(&emitter)) {
    yaml_parser_delete(&parser);
    return 1;
  }

  /* Set the parser parameters. */

  yaml_parser_set_input_string(&parser, data, size);

  /* Set the emitter parameters. */
  yaml_output_buffer_t out = {/*buf=*/NULL, /*size=*/0};
  yaml_emitter_set_output(&emitter, yaml_write_handler, &out);

  yaml_emitter_set_canonical(&emitter, is_canonical);
  yaml_emitter_set_unicode(&emitter, is_unicode);

  /* Create and emit the STREAM-START event. */

  if (!yaml_emitter_open(&emitter))
    goto error;

  /* Create a output_document object. */

  if (!yaml_document_initialize(&output_document, NULL, NULL, NULL, 0, 0))
    goto error;

  /* Create the root sequence. */

  root = yaml_document_add_sequence(&output_document, NULL,
                                    YAML_BLOCK_SEQUENCE_STYLE);
  if (!root)
    goto error;

  /* Loop through the input events. */

  while (!done) {
    int properties, key, value, map, seq;

    /* Get the next event. */

    if (!yaml_parser_parse(&parser, &input_event))
      goto error;

    /* Check if this is the stream end. */

    done = (input_event.type == YAML_STREAM_END_EVENT);

    /* Create a mapping node and attach it to the root sequence. */

    properties = yaml_document_add_mapping(&output_document, NULL,
                                           YAML_BLOCK_MAPPING_STYLE);
    if (!properties)
      goto error;
    if (!yaml_document_append_sequence_item(&output_document, root, properties))
      goto error;

    /* Analyze the event. */

    switch (input_event.type) {
    case YAML_STREAM_START_EVENT:

      /* Add 'type': 'STREAM-START'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"STREAM-START", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Add 'encoding': <encoding>. */

      if (input_event.data.stream_start.encoding) {
        yaml_encoding_t encoding = input_event.data.stream_start.encoding;

        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"encoding", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(
            &output_document, NULL,
            (encoding == YAML_UTF8_ENCODING
                 ? (yaml_char_t *)"utf-8"
                 : encoding == YAML_UTF16LE_ENCODING
                       ? (yaml_char_t *)"utf-16-le"
                       : encoding == YAML_UTF16BE_ENCODING
                             ? (yaml_char_t *)"utf-16-be"
                             : (yaml_char_t *)"unknown"),
            -1, YAML_PLAIN_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      break;

    case YAML_STREAM_END_EVENT:

      /* Add 'type': 'STREAM-END'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"STREAM-END", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      break;

    case YAML_DOCUMENT_START_EVENT:

      /* Add 'type': 'DOCUMENT-START'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"DOCUMENT-START", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Display the output_document version numbers. */

      if (input_event.data.document_start.version_directive) {
        yaml_version_directive_t *version =
            input_event.data.document_start.version_directive;
        char number[64];

        /* Add 'version': {}. */

        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"version", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        map = yaml_document_add_mapping(&output_document, NULL,
                                        YAML_FLOW_MAPPING_STYLE);
        if (!map)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, map))
          goto error;

        /* Add 'major': <number>. */

        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"major", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        sprintf(number, "%d", version->major);
        value = yaml_document_add_scalar(
            &output_document, (yaml_char_t *)YAML_INT_TAG,
            (yaml_char_t *)number, -1, YAML_PLAIN_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, map, key,
                                               value))
          goto error;

        /* Add 'minor': <number>. */

        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"minor", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        sprintf(number, "%d", version->minor);
        value = yaml_document_add_scalar(
            &output_document, (yaml_char_t *)YAML_INT_TAG,
            (yaml_char_t *)number, -1, YAML_PLAIN_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, map, key,
                                               value))
          goto error;
      }

      /* Display the output_document tag directives. */

      if (input_event.data.document_start.tag_directives.start !=
          input_event.data.document_start.tag_directives.end) {
        yaml_tag_directive_t *tag;

        /* Add 'tags': []. */

        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"tags", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        seq = yaml_document_add_sequence(&output_document, NULL,
                                         YAML_BLOCK_SEQUENCE_STYLE);
        if (!seq)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, seq))
          goto error;

        for (tag = input_event.data.document_start.tag_directives.start;
             tag != input_event.data.document_start.tag_directives.end; tag++) {
          /* Add {}. */

          map = yaml_document_add_mapping(&output_document, NULL,
                                          YAML_FLOW_MAPPING_STYLE);
          if (!map)
            goto error;
          if (!yaml_document_append_sequence_item(&output_document, seq, map))
            goto error;

          /* Add 'handle': <handle>. */

          key = yaml_document_add_scalar(&output_document, NULL,
                                         (yaml_char_t *)"handle", -1,
                                         YAML_PLAIN_SCALAR_STYLE);
          if (!key)
            goto error;
          value = yaml_document_add_scalar(&output_document, NULL, tag->handle,
                                           -1, YAML_DOUBLE_QUOTED_SCALAR_STYLE);
          if (!value)
            goto error;
          if (!yaml_document_append_mapping_pair(&output_document, map, key,
                                                 value))
            goto error;

          /* Add 'prefix': <prefix>. */

          key = yaml_document_add_scalar(&output_document, NULL,
                                         (yaml_char_t *)"prefix", -1,
                                         YAML_PLAIN_SCALAR_STYLE);
          if (!key)
            goto error;
          value = yaml_document_add_scalar(&output_document, NULL, tag->prefix,
                                           -1, YAML_DOUBLE_QUOTED_SCALAR_STYLE);
          if (!value)
            goto error;
          if (!yaml_document_append_mapping_pair(&output_document, map, key,
                                                 value))
            goto error;
        }
      }

      /* Add 'implicit': <flag>. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"implicit", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(
          &output_document, (yaml_char_t *)YAML_BOOL_TAG,
          (input_event.data.document_start.implicit ? (yaml_char_t *)"true"
                                                    : (yaml_char_t *)"false"),
          -1, YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      break;

    case YAML_DOCUMENT_END_EVENT:

      /* Add 'type': 'DOCUMENT-END'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"DOCUMENT-END", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Add 'implicit': <flag>. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"implicit", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(
          &output_document, (yaml_char_t *)YAML_BOOL_TAG,
          (input_event.data.document_end.implicit ? (yaml_char_t *)"true"
                                                  : (yaml_char_t *)"false"),
          -1, YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      break;

    case YAML_ALIAS_EVENT:

      /* Add 'type': 'ALIAS'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"ALIAS", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Add 'anchor': <anchor>. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"anchor", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       input_event.data.alias.anchor, -1,
                                       YAML_DOUBLE_QUOTED_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      break;

    case YAML_SCALAR_EVENT:

      /* Add 'type': 'SCALAR'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"SCALAR", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Add 'anchor': <anchor>. */

      if (input_event.data.scalar.anchor) {
        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"anchor", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(&output_document, NULL,
                                         input_event.data.scalar.anchor, -1,
                                         YAML_DOUBLE_QUOTED_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      /* Add 'tag': <tag>. */

      if (input_event.data.scalar.tag) {
        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"tag", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(&output_document, NULL,
                                         input_event.data.scalar.tag, -1,
                                         YAML_DOUBLE_QUOTED_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      /* Add 'value': <value>. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"value", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(
          &output_document, NULL, input_event.data.scalar.value,
          input_event.data.scalar.length, YAML_DOUBLE_QUOTED_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Display if the scalar tag is implicit. */

      /* Add 'implicit': {} */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"version", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      map = yaml_document_add_mapping(&output_document, NULL,
                                      YAML_FLOW_MAPPING_STYLE);
      if (!map)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             map))
        goto error;

      /* Add 'plain': <flag>. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"plain", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(
          &output_document, (yaml_char_t *)YAML_BOOL_TAG,
          (input_event.data.scalar.plain_implicit ? (yaml_char_t *)"true"
                                                  : (yaml_char_t *)"false"),
          -1, YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, map, key, value))
        goto error;

      /* Add 'quoted': <flag>. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"quoted", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(
          &output_document, (yaml_char_t *)YAML_BOOL_TAG,
          (input_event.data.scalar.quoted_implicit ? (yaml_char_t *)"true"
                                                   : (yaml_char_t *)"false"),
          -1, YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, map, key, value))
        goto error;

      /* Display the style information. */

      if (input_event.data.scalar.style) {
        yaml_scalar_style_t style = input_event.data.scalar.style;

        /* Add 'style': <style>. */

        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"style", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(
            &output_document, NULL,
            (yaml_char_t
                 *)(style == YAML_PLAIN_SCALAR_STYLE
                        ? "plain"
                        : style == YAML_SINGLE_QUOTED_SCALAR_STYLE
                              ? "single-quoted"
                              : style == YAML_DOUBLE_QUOTED_SCALAR_STYLE
                                    ? "double-quoted"
                                    : style == YAML_LITERAL_SCALAR_STYLE
                                          ? "literal"
                                          : style == YAML_FOLDED_SCALAR_STYLE
                                                ? "folded"
                                                : "unknown"),
            -1, YAML_PLAIN_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      break;

    case YAML_SEQUENCE_START_EVENT:

      /* Add 'type': 'SEQUENCE-START'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"SEQUENCE-START", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Add 'anchor': <anchor>. */

      if (input_event.data.sequence_start.anchor) {
        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"anchor", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(&output_document, NULL,
                                         input_event.data.sequence_start.anchor,
                                         -1, YAML_DOUBLE_QUOTED_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      /* Add 'tag': <tag>. */

      if (input_event.data.sequence_start.tag) {
        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"tag", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(&output_document, NULL,
                                         input_event.data.sequence_start.tag,
                                         -1, YAML_DOUBLE_QUOTED_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      /* Add 'implicit': <flag>. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"implicit", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(
          &output_document, (yaml_char_t *)YAML_BOOL_TAG,
          (input_event.data.sequence_start.implicit ? (yaml_char_t *)"true"
                                                    : (yaml_char_t *)"false"),
          -1, YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Display the style information. */

      if (input_event.data.sequence_start.style) {
        yaml_sequence_style_t style = input_event.data.sequence_start.style;

        /* Add 'style': <style>. */

        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"style", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(
            &output_document, NULL,
            (yaml_char_t *)(style == YAML_BLOCK_SEQUENCE_STYLE
                                ? "block"
                                : style == YAML_FLOW_SEQUENCE_STYLE
                                      ? "flow"
                                      : "unknown"),
            -1, YAML_PLAIN_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      break;

    case YAML_SEQUENCE_END_EVENT:

      /* Add 'type': 'SEQUENCE-END'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"SEQUENCE-END", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      break;

    case YAML_MAPPING_START_EVENT:

      /* Add 'type': 'MAPPING-START'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"MAPPING-START", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Add 'anchor': <anchor>. */

      if (input_event.data.mapping_start.anchor) {
        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"anchor", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(&output_document, NULL,
                                         input_event.data.mapping_start.anchor,
                                         -1, YAML_DOUBLE_QUOTED_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      /* Add 'tag': <tag>. */

      if (input_event.data.mapping_start.tag) {
        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"tag", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(&output_document, NULL,
                                         input_event.data.mapping_start.tag, -1,
                                         YAML_DOUBLE_QUOTED_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      /* Add 'implicit': <flag>. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"implicit", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(
          &output_document, (yaml_char_t *)YAML_BOOL_TAG,
          (yaml_char_t *)(input_event.data.mapping_start.implicit ? "true"
                                                                  : "false"),
          -1, YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      /* Display the style information. */

      if (input_event.data.sequence_start.style) {
        yaml_sequence_style_t style = input_event.data.sequence_start.style;

        /* Add 'style': <style>. */

        key = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"style", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
        if (!key)
          goto error;
        value = yaml_document_add_scalar(
            &output_document, NULL,
            (yaml_char_t *)(style == YAML_BLOCK_MAPPING_STYLE
                                ? "block"
                                : style == YAML_FLOW_MAPPING_STYLE ? "flow"
                                                                   : "unknown"),
            -1, YAML_PLAIN_SCALAR_STYLE);
        if (!value)
          goto error;
        if (!yaml_document_append_mapping_pair(&output_document, properties,
                                               key, value))
          goto error;
      }

      break;

    case YAML_MAPPING_END_EVENT:

      /* Add 'type': 'MAPPING-END'. */

      key = yaml_document_add_scalar(&output_document, NULL,
                                     (yaml_char_t *)"type", -1,
                                     YAML_PLAIN_SCALAR_STYLE);
      if (!key)
        goto error;
      value = yaml_document_add_scalar(&output_document, NULL,
                                       (yaml_char_t *)"MAPPING-END", -1,
                                       YAML_PLAIN_SCALAR_STYLE);
      if (!value)
        goto error;
      if (!yaml_document_append_mapping_pair(&output_document, properties, key,
                                             value))
        goto error;

      break;

    default:
      /* It couldn't really happen. */
      break;
    }

    /* Delete the event object. */

    yaml_event_delete(&input_event);
  }

  if (!yaml_emitter_dump(&emitter, &output_document))
    goto error;

  yaml_emitter_close(&emitter);

error:

  free(out.buf);

  yaml_event_delete(&input_event);
  yaml_document_delete(&output_document);
  yaml_parser_delete(&parser);
  yaml_emitter_delete(&emitter);

  return 0;
}
