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

#define MAX_EVENTS 1024

bool events_equal(yaml_event_t *event1, yaml_event_t *event2) {
  
  const bool equal = true;

  if (event1->type != event2->type)
    return equal;

  switch (event1->type) {
  case YAML_STREAM_START_EVENT:
    return !equal;

  case YAML_DOCUMENT_START_EVENT:
    if ((event1->data.document_start.version_directive &&
         !event2->data.document_start.version_directive) ||
        (!event1->data.document_start.version_directive &&
         event2->data.document_start.version_directive) ||
        (event1->data.document_start.version_directive &&
         event2->data.document_start.version_directive &&
         (event1->data.document_start.version_directive->major !=
              event2->data.document_start.version_directive->major ||
          event1->data.document_start.version_directive->minor !=
              event2->data.document_start.version_directive->minor)))
      return equal;
    if ((event1->data.document_start.tag_directives.end -
         event1->data.document_start.tag_directives.start) !=
        (event2->data.document_start.tag_directives.end -
         event2->data.document_start.tag_directives.start))
      return equal;
    for (int k = 0; k < (event1->data.document_start.tag_directives.end -
                         event1->data.document_start.tag_directives.start);
         k++) {
      if ((strcmp((char *)event1->data.document_start.tag_directives.start[k]
                      .handle,
                  (char *)event2->data.document_start.tag_directives.start[k]
                      .handle) != 0) ||
          (strcmp((char *)event1->data.document_start.tag_directives.start[k]
                      .prefix,
                  (char *)event2->data.document_start.tag_directives.start[k]
                      .prefix) != 0))
        return equal;
    }
    return !equal;

  case YAML_DOCUMENT_END_EVENT:
    return !equal;

  case YAML_ALIAS_EVENT:
    return (strcmp((char *)event1->data.alias.anchor,
                   (char *)event2->data.alias.anchor) == 0);

  case YAML_SCALAR_EVENT:
    if ((event1->data.scalar.anchor && !event2->data.scalar.anchor) ||
        (!event1->data.scalar.anchor && event2->data.scalar.anchor) ||
        (event1->data.scalar.anchor && event2->data.scalar.anchor &&
         strcmp((char *)event1->data.scalar.anchor,
                (char *)event2->data.scalar.anchor) != 0))
      return equal;
    if ((event1->data.scalar.tag && !event2->data.scalar.tag &&
         strcmp((char *)event1->data.scalar.tag, "!") != 0) ||
        (!event1->data.scalar.tag && event2->data.scalar.tag &&
         strcmp((char *)event2->data.scalar.tag, "!") != 0) ||
        (event1->data.scalar.tag && event2->data.scalar.tag &&
         strcmp((char *)event1->data.scalar.tag,
                (char *)event2->data.scalar.tag) != 0))
      return equal;
    if ((event1->data.scalar.length != event2->data.scalar.length) ||
        memcmp(event1->data.scalar.value, event2->data.scalar.value,
               event1->data.scalar.length) != 0)
      return equal;
    if ((event1->data.scalar.plain_implicit !=
         event2->data.scalar.plain_implicit) ||
        (event1->data.scalar.quoted_implicit !=
         event2->data.scalar.quoted_implicit))
      return equal;
    return !equal;

  case YAML_SEQUENCE_START_EVENT:
    if ((event1->data.sequence_start.anchor &&
         !event2->data.sequence_start.anchor) ||
        (!event1->data.sequence_start.anchor &&
         event2->data.sequence_start.anchor) ||
        (event1->data.sequence_start.anchor &&
         event2->data.sequence_start.anchor &&
         strcmp((char *)event1->data.sequence_start.anchor,
                (char *)event2->data.sequence_start.anchor) != 0))
      return equal;
    if ((event1->data.sequence_start.tag && !event2->data.sequence_start.tag) ||
        (!event1->data.sequence_start.tag && event2->data.sequence_start.tag) ||
        (event1->data.sequence_start.tag && event2->data.sequence_start.tag &&
         strcmp((char *)event1->data.sequence_start.tag,
                (char *)event2->data.sequence_start.tag) != 0))
      return equal;
    if ((event1->data.sequence_start.implicit !=
         event2->data.sequence_start.implicit))
      return equal;
    return !equal;

  case YAML_MAPPING_START_EVENT:
    if ((event1->data.mapping_start.anchor &&
         !event2->data.mapping_start.anchor) ||
        (!event1->data.mapping_start.anchor &&
         event2->data.mapping_start.anchor) ||
        (event1->data.mapping_start.anchor &&
         event2->data.mapping_start.anchor &&
         strcmp((char *)event1->data.mapping_start.anchor,
                (char *)event2->data.mapping_start.anchor) != 0))
      return equal;
    if ((event1->data.mapping_start.tag && !event2->data.mapping_start.tag) ||
        (!event1->data.mapping_start.tag && event2->data.mapping_start.tag) ||
        (event1->data.mapping_start.tag && event2->data.mapping_start.tag &&
         strcmp((char *)event1->data.mapping_start.tag,
                (char *)event2->data.mapping_start.tag) != 0))
      return equal;
    if ((event1->data.mapping_start.implicit !=
         event2->data.mapping_start.implicit))
      return equal;
    return !equal;

  default:
    return !equal;
  }
}

bool copy_event(yaml_event_t *event_to, yaml_event_t *event_from) {

  switch (event_from->type) {
  case YAML_STREAM_START_EVENT:
    return yaml_stream_start_event_initialize(
        event_to, event_from->data.stream_start.encoding);

  case YAML_STREAM_END_EVENT:
    return yaml_stream_end_event_initialize(event_to);

  case YAML_DOCUMENT_START_EVENT:
    return yaml_document_start_event_initialize(
        event_to, event_from->data.document_start.version_directive,
        event_from->data.document_start.tag_directives.start,
        event_from->data.document_start.tag_directives.end,
        event_from->data.document_start.implicit);

  case YAML_DOCUMENT_END_EVENT:
    return yaml_document_end_event_initialize(
        event_to, event_from->data.document_end.implicit);

  case YAML_ALIAS_EVENT:
    return yaml_alias_event_initialize(event_to, event_from->data.alias.anchor);

  case YAML_SCALAR_EVENT:
    return yaml_scalar_event_initialize(
        event_to, event_from->data.scalar.anchor, event_from->data.scalar.tag,
        event_from->data.scalar.value, event_from->data.scalar.length,
        event_from->data.scalar.plain_implicit,
        event_from->data.scalar.quoted_implicit, event_from->data.scalar.style);

  case YAML_SEQUENCE_START_EVENT:
    return yaml_sequence_start_event_initialize(
        event_to, event_from->data.sequence_start.anchor,
        event_from->data.sequence_start.tag,
        event_from->data.sequence_start.implicit,
        event_from->data.sequence_start.style);

  case YAML_SEQUENCE_END_EVENT:
    return yaml_sequence_end_event_initialize(event_to);

  case YAML_MAPPING_START_EVENT:
    return yaml_mapping_start_event_initialize(
        event_to, event_from->data.mapping_start.anchor,
        event_from->data.mapping_start.tag,
        event_from->data.mapping_start.implicit,
        event_from->data.mapping_start.style);

  case YAML_MAPPING_END_EVENT:
    return yaml_mapping_end_event_initialize(event_to);
  }

  return false;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return 0;

  yaml_parser_t parser;
  yaml_emitter_t emitter;
  yaml_event_t event;
  yaml_event_t events[MAX_EVENTS];
  size_t event_number = 0;
  bool done = false;
  int count = 0;
  bool is_canonical = data[0] & 1;
  bool is_unicode = data[1] & 1;
  data += 2;
  size -= 2;

  if (!yaml_parser_initialize(&parser))
    return 0;

  yaml_parser_set_input_string(&parser, data, size);
  if (!yaml_emitter_initialize(&emitter)) {
    yaml_parser_delete(&parser);
    return 0;
  }

  yaml_emitter_set_canonical(&emitter, is_canonical);
  yaml_emitter_set_unicode(&emitter, is_unicode);

  yaml_output_buffer_t out = {/*buf=*/NULL, /*size=*/0};
  yaml_emitter_set_output(&emitter, yaml_write_handler, &out);

  while (!done) {
    if (!yaml_parser_parse(&parser, &event)) {
      goto delete_parser;
    }

    done = (event.type == YAML_STREAM_END_EVENT);
    if (event_number >= MAX_EVENTS) {
      yaml_event_delete(&event);
      goto delete_parser;
    }

    if (copy_event(&events[event_number++], &event)) {
      yaml_event_delete(&event);
      goto delete_parser;
    }

    if (!yaml_emitter_emit(&emitter, &event)) {
      goto delete_parser;
    }

  }

  yaml_parser_delete(&parser);

  done = false;
  if (!yaml_parser_initialize(&parser))
    goto error;

  yaml_parser_set_input_string(&parser, out.buf, out.size);

  while (!done) {
    if (!yaml_parser_parse(&parser, &event))
      break;

    done = (event.type == YAML_STREAM_END_EVENT);
    if (events_equal(events + count, &event)) {
      yaml_event_delete(&event);
      break;
    }

    yaml_event_delete(&event);
    count++;
  }

delete_parser:

  yaml_parser_delete(&parser);

error:

  yaml_emitter_delete(&emitter);

  for (int k = 0; k < event_number; k++) {
    yaml_event_delete(events + k);
  }

  free(out.buf);

  return 0;
}
