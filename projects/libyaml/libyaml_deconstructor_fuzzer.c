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
  yaml_event_t output_event;

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

  if (!yaml_stream_start_event_initialize(&output_event, YAML_UTF8_ENCODING))
    goto error;
  if (!yaml_emitter_emit(&emitter, &output_event))
    goto error;

  /* Create and emit the DOCUMENT-START event. */

  if (!yaml_document_start_event_initialize(&output_event, NULL, NULL, NULL, 0))
    goto error;
  if (!yaml_emitter_emit(&emitter, &output_event))
    goto error;

  /* Create and emit the SEQUENCE-START event. */

  if (!yaml_sequence_start_event_initialize(
          &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:seq", 1,
          YAML_BLOCK_SEQUENCE_STYLE))
    goto error;
  if (!yaml_emitter_emit(&emitter, &output_event))
    goto error;

  /* Loop through the input events. */

  while (!done) {
    /* Get the next event. */

    if (!yaml_parser_parse(&parser, &input_event))
      goto error;

    /* Check if this is the stream end. */

    done = (input_event.type == YAML_STREAM_END_EVENT);

    /* Create and emit a MAPPING-START event. */

    if (!yaml_mapping_start_event_initialize(
            &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:map", 1,
            YAML_BLOCK_MAPPING_STYLE))
      goto error;
    if (!yaml_emitter_emit(&emitter, &output_event))
      goto error;

    /* Analyze the event. */

    switch (input_event.type) {
    case YAML_STREAM_START_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'STREAM-START'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"STREAM-START", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display encoding information. */

      if (input_event.data.stream_start.encoding) {
        yaml_encoding_t encoding = input_event.data.stream_start.encoding;

        /* Write 'encoding'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"encoding", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the stream encoding. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)(encoding == YAML_UTF8_ENCODING
                                    ? "utf-8"
                                    : encoding == YAML_UTF16LE_ENCODING
                                          ? "utf-16-le"
                                          : encoding == YAML_UTF16BE_ENCODING
                                                ? "utf-16-be"
                                                : "unknown"),
                -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      break;

    case YAML_STREAM_END_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'STREAM-END'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"STREAM-END", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      break;

    case YAML_DOCUMENT_START_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'DOCUMENT-START'. */

      if (!yaml_scalar_event_initialize(&output_event, NULL,
                                        (yaml_char_t *)"tag:yaml.org,2002:str",
                                        (yaml_char_t *)"DOCUMENT-START", -1, 1,
                                        1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display the document version numbers. */

      if (input_event.data.document_start.version_directive) {
        yaml_version_directive_t *version =
            input_event.data.document_start.version_directive;
        char number[64];

        /* Write 'version'. */
        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"version", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write '{'. */

        if (!yaml_mapping_start_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:map", 1,
                YAML_FLOW_MAPPING_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write 'major'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"major", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write a number. */

        sprintf(number, "%d", version->major);
        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:int",
                (yaml_char_t *)number, -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write 'minor'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"minor", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write a number. */

        sprintf(number, "%d", version->minor);
        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:int",
                (yaml_char_t *)number, -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write '}'. */

        if (!yaml_mapping_end_event_initialize(&output_event))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      /* Display the document tag directives. */

      if (input_event.data.document_start.tag_directives.start !=
          input_event.data.document_start.tag_directives.end) {
        yaml_tag_directive_t *tag;

        /* Write 'tags'. */
        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"tags", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Start a block sequence. */

        if (!yaml_sequence_start_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:seq", 1,
                YAML_BLOCK_SEQUENCE_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        for (tag = input_event.data.document_start.tag_directives.start;
             tag != input_event.data.document_start.tag_directives.end; tag++) {
          /* Write '{'. */

          if (!yaml_mapping_start_event_initialize(
                  &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:map",
                  1, YAML_FLOW_MAPPING_STYLE))
            goto error;
          if (!yaml_emitter_emit(&emitter, &output_event))
            goto error;

          /* Write 'handle'. */

          if (!yaml_scalar_event_initialize(
                  &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                  (yaml_char_t *)"handle", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
            goto error;
          if (!yaml_emitter_emit(&emitter, &output_event))
            goto error;

          /* Write the tag directive handle. */

          if (!yaml_scalar_event_initialize(
                  &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                  (yaml_char_t *)tag->handle, -1, 0, 1,
                  YAML_DOUBLE_QUOTED_SCALAR_STYLE))
            goto error;
          if (!yaml_emitter_emit(&emitter, &output_event))
            goto error;

          /* Write 'prefix'. */

          if (!yaml_scalar_event_initialize(
                  &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                  (yaml_char_t *)"prefix", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
            goto error;
          if (!yaml_emitter_emit(&emitter, &output_event))
            goto error;

          /* Write the tag directive prefix. */

          if (!yaml_scalar_event_initialize(
                  &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                  (yaml_char_t *)tag->prefix, -1, 0, 1,
                  YAML_DOUBLE_QUOTED_SCALAR_STYLE))
            goto error;
          if (!yaml_emitter_emit(&emitter, &output_event))
            goto error;

          /* Write '}'. */

          if (!yaml_mapping_end_event_initialize(&output_event))
            goto error;
          if (!yaml_emitter_emit(&emitter, &output_event))
            goto error;
        }

        /* End a block sequence. */

        if (!yaml_sequence_end_event_initialize(&output_event))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      /* Write 'implicit'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"implicit", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write if the document is implicit. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:bool",
              (yaml_char_t *)(input_event.data.document_start.implicit
                                  ? "true"
                                  : "false"),
              -1, 1, 0, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      break;

    case YAML_DOCUMENT_END_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'DOCUMENT-END'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"DOCUMENT-END", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'implicit'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"implicit", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write if the document is implicit. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:bool",
              (yaml_char_t *)(input_event.data.document_end.implicit ? "true"
                                                                     : "false"),
              -1, 1, 0, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      break;

    case YAML_ALIAS_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'ALIAS'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"ALIAS", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'anchor'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"anchor", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write the alias anchor. */

      if (!yaml_scalar_event_initialize(&output_event, NULL,
                                        (yaml_char_t *)"tag:yaml.org,2002:str",
                                        input_event.data.alias.anchor, -1, 0, 1,
                                        YAML_DOUBLE_QUOTED_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      break;

    case YAML_SCALAR_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'SCALAR'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"SCALAR", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display the scalar anchor. */

      if (input_event.data.scalar.anchor) {
        /* Write 'anchor'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"anchor", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the scalar anchor. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                input_event.data.scalar.anchor, -1, 0, 1,
                YAML_DOUBLE_QUOTED_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      /* Display the scalar tag. */

      if (input_event.data.scalar.tag) {
        /* Write 'tag'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"tag", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the scalar tag. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                input_event.data.scalar.tag, -1, 0, 1,
                YAML_DOUBLE_QUOTED_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      /* Display the scalar value. */

      /* Write 'value'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"value", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write the scalar value. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              input_event.data.scalar.value, input_event.data.scalar.length, 0,
              1, YAML_DOUBLE_QUOTED_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display if the scalar tag is implicit. */

      /* Write 'implicit'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"implicit", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write '{'. */

      if (!yaml_mapping_start_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:map", 1,
              YAML_FLOW_MAPPING_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'plain'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"plain", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write if the scalar is implicit in the plain style. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:bool",
              (yaml_char_t *)(input_event.data.scalar.plain_implicit ? "true"
                                                                     : "false"),
              -1, 1, 0, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'quoted'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"non-plain", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write if the scalar is implicit in a non-plain style. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:bool",
              (yaml_char_t *)(input_event.data.scalar.quoted_implicit
                                  ? "true"
                                  : "false"),
              -1, 1, 0, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write '}'. */

      if (!yaml_mapping_end_event_initialize(&output_event))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display the style information. */

      if (input_event.data.scalar.style) {
        yaml_scalar_style_t style = input_event.data.scalar.style;

        /* Write 'style'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"style", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the scalar style. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t
                     *)(style == YAML_PLAIN_SCALAR_STYLE
                            ? "plain"
                            : style == YAML_SINGLE_QUOTED_SCALAR_STYLE
                                  ? "single-quoted"
                                  : style == YAML_DOUBLE_QUOTED_SCALAR_STYLE
                                        ? "double-quoted"
                                        : style == YAML_LITERAL_SCALAR_STYLE
                                              ? "literal"
                                              : style ==
                                                        YAML_FOLDED_SCALAR_STYLE
                                                    ? "folded"
                                                    : "unknown"),
                -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      break;

    case YAML_SEQUENCE_START_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'SEQUENCE-START'. */

      if (!yaml_scalar_event_initialize(&output_event, NULL,
                                        (yaml_char_t *)"tag:yaml.org,2002:str",
                                        (yaml_char_t *)"SEQUENCE-START", -1, 1,
                                        1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display the sequence anchor. */

      if (input_event.data.sequence_start.anchor) {
        /* Write 'anchor'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"anchor", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the sequence anchor. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                input_event.data.sequence_start.anchor, -1, 0, 1,
                YAML_DOUBLE_QUOTED_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      /* Display the sequence tag. */

      if (input_event.data.sequence_start.tag) {
        /* Write 'tag'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"tag", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the sequence tag. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                input_event.data.sequence_start.tag, -1, 0, 1,
                YAML_DOUBLE_QUOTED_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      /* Write 'implicit'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"implicit", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write if the sequence tag is implicit. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:bool",
              (yaml_char_t *)(input_event.data.sequence_start.implicit
                                  ? "true"
                                  : "false"),
              -1, 1, 0, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display the style information. */

      if (input_event.data.sequence_start.style) {
        yaml_sequence_style_t style = input_event.data.sequence_start.style;

        /* Write 'style'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"style", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the scalar style. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)(style == YAML_BLOCK_SEQUENCE_STYLE
                                    ? "block"
                                    : style == YAML_FLOW_SEQUENCE_STYLE
                                          ? "flow"
                                          : "unknown"),
                -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      break;

    case YAML_SEQUENCE_END_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'SEQUENCE-END'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"SEQUENCE-END", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      break;

    case YAML_MAPPING_START_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'MAPPING-START'. */

      if (!yaml_scalar_event_initialize(&output_event, NULL,
                                        (yaml_char_t *)"tag:yaml.org,2002:str",
                                        (yaml_char_t *)"MAPPING-START", -1, 1,
                                        1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display the mapping anchor. */

      if (input_event.data.mapping_start.anchor) {
        /* Write 'anchor'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"anchor", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the mapping anchor. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                input_event.data.mapping_start.anchor, -1, 0, 1,
                YAML_DOUBLE_QUOTED_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      /* Display the mapping tag. */

      if (input_event.data.mapping_start.tag) {
        /* Write 'tag'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"tag", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the mapping tag. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                input_event.data.mapping_start.tag, -1, 0, 1,
                YAML_DOUBLE_QUOTED_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      /* Write 'implicit'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"implicit", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write if the mapping tag is implicit. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:bool",
              (yaml_char_t *)(input_event.data.mapping_start.implicit
                                  ? "true"
                                  : "false"),
              -1, 1, 0, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Display the style information. */

      if (input_event.data.mapping_start.style) {
        yaml_mapping_style_t style = input_event.data.mapping_start.style;

        /* Write 'style'. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)"style", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;

        /* Write the scalar style. */

        if (!yaml_scalar_event_initialize(
                &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
                (yaml_char_t *)(style == YAML_BLOCK_MAPPING_STYLE
                                    ? "block"
                                    : style == YAML_FLOW_MAPPING_STYLE
                                          ? "flow"
                                          : "unknown"),
                -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
          goto error;
        if (!yaml_emitter_emit(&emitter, &output_event))
          goto error;
      }

      break;

    case YAML_MAPPING_END_EVENT:

      /* Write 'type'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"type", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      /* Write 'MAPPING-END'. */

      if (!yaml_scalar_event_initialize(
              &output_event, NULL, (yaml_char_t *)"tag:yaml.org,2002:str",
              (yaml_char_t *)"MAPPING-END", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE))
        goto error;
      if (!yaml_emitter_emit(&emitter, &output_event))
        goto error;

      break;

    default:
      /* It couldn't really happen. */
      break;
    }

    /* Delete the event object. */

    yaml_event_delete(&input_event);

    /* Create and emit a MAPPING-END event. */

    if (!yaml_mapping_end_event_initialize(&output_event))
      goto error;
    if (!yaml_emitter_emit(&emitter, &output_event))
      goto error;
  }

  /* Create and emit the SEQUENCE-END event. */

  if (!yaml_sequence_end_event_initialize(&output_event))
    goto error;
  if (!yaml_emitter_emit(&emitter, &output_event))
    goto error;

  /* Create and emit the DOCUMENT-END event. */

  if (!yaml_document_end_event_initialize(&output_event, 0))
    goto error;
  if (!yaml_emitter_emit(&emitter, &output_event))
    goto error;

  /* Create and emit the STREAM-END event. */

  if (!yaml_stream_end_event_initialize(&output_event))
    goto error;
  yaml_emitter_emit(&emitter, &output_event);

error:

  free(out.buf);

  yaml_event_delete(&input_event);
  yaml_parser_delete(&parser);
  yaml_emitter_delete(&emitter);

  return 0;
}
