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
#include <stdbool.h>

#ifdef NDEBUG
#undef NDEBUG
#endif

#define BUFFER_SIZE 65536
#define MAX_EVENTS   1024

int compare_events(yaml_event_t *event1, yaml_event_t *event2)
{
    int k;

    if (event1->type != event2->type)
        return 0;

    switch (event1->type)
    {
        case YAML_STREAM_START_EVENT:
            return 1;
            /* return (event1->data.stream_start.encoding ==
                    event2->data.stream_start.encoding); */

        case YAML_DOCUMENT_START_EVENT:
            if ((event1->data.document_start.version_directive && !event2->data.document_start.version_directive)
                    || (!event1->data.document_start.version_directive && event2->data.document_start.version_directive)
                    || (event1->data.document_start.version_directive && event2->data.document_start.version_directive
                        && (event1->data.document_start.version_directive->major != event2->data.document_start.version_directive->major
                            || event1->data.document_start.version_directive->minor != event2->data.document_start.version_directive->minor)))
                return 0;
            if ((event1->data.document_start.tag_directives.end - event1->data.document_start.tag_directives.start) !=
                    (event2->data.document_start.tag_directives.end - event2->data.document_start.tag_directives.start))
                return 0;
            for (int k = 0; k < (event1->data.document_start.tag_directives.end - event1->data.document_start.tag_directives.start); k ++) {
                if ((strcmp((char *)event1->data.document_start.tag_directives.start[k].handle,
                                (char *)event2->data.document_start.tag_directives.start[k].handle) != 0)
                        || (strcmp((char *)event1->data.document_start.tag_directives.start[k].prefix,
                            (char *)event2->data.document_start.tag_directives.start[k].prefix) != 0))
                    return 0;
            }
            /* if (event1->data.document_start.implicit != event2->data.document_start.implicit)
                return 0; */
            return 1;

        case YAML_DOCUMENT_END_EVENT:
            return 1;
            /* return (event1->data.document_end.implicit ==
                    event2->data.document_end.implicit); */

        case YAML_ALIAS_EVENT:
            return (strcmp((char *)event1->data.alias.anchor,
                        (char *)event2->data.alias.anchor) == 0);

        case YAML_SCALAR_EVENT:
            if ((event1->data.scalar.anchor && !event2->data.scalar.anchor)
                    || (!event1->data.scalar.anchor && event2->data.scalar.anchor)
                    || (event1->data.scalar.anchor && event2->data.scalar.anchor
                        && strcmp((char *)event1->data.scalar.anchor,
                            (char *)event2->data.scalar.anchor) != 0))
                return 0;
            if ((event1->data.scalar.tag && !event2->data.scalar.tag
                        && strcmp((char *)event1->data.scalar.tag, "!") != 0)
                    || (!event1->data.scalar.tag && event2->data.scalar.tag
                        && strcmp((char *)event2->data.scalar.tag, "!") != 0)
                    || (event1->data.scalar.tag && event2->data.scalar.tag
                        && strcmp((char *)event1->data.scalar.tag,
                            (char *)event2->data.scalar.tag) != 0))
                return 0;
            if ((event1->data.scalar.length != event2->data.scalar.length)
                    || memcmp(event1->data.scalar.value, event2->data.scalar.value,
                        event1->data.scalar.length) != 0)
                return 0;
            if ((event1->data.scalar.plain_implicit != event2->data.scalar.plain_implicit)
                    || (event2->data.scalar.quoted_implicit != event2->data.scalar.quoted_implicit)
                    /* || (event2->data.scalar.style != event2->data.scalar.style) */)
                return 0;
            return 1;

        case YAML_SEQUENCE_START_EVENT:
            if ((event1->data.sequence_start.anchor && !event2->data.sequence_start.anchor)
                    || (!event1->data.sequence_start.anchor && event2->data.sequence_start.anchor)
                    || (event1->data.sequence_start.anchor && event2->data.sequence_start.anchor
                        && strcmp((char *)event1->data.sequence_start.anchor,
                            (char *)event2->data.sequence_start.anchor) != 0))
                return 0;
            if ((event1->data.sequence_start.tag && !event2->data.sequence_start.tag)
                    || (!event1->data.sequence_start.tag && event2->data.sequence_start.tag)
                    || (event1->data.sequence_start.tag && event2->data.sequence_start.tag
                        && strcmp((char *)event1->data.sequence_start.tag,
                            (char *)event2->data.sequence_start.tag) != 0))
                return 0;
            if ((event1->data.sequence_start.implicit != event2->data.sequence_start.implicit)
                    /* || (event2->data.sequence_start.style != event2->data.sequence_start.style) */)
                return 0;
            return 1;

        case YAML_MAPPING_START_EVENT:
            if ((event1->data.mapping_start.anchor && !event2->data.mapping_start.anchor)
                    || (!event1->data.mapping_start.anchor && event2->data.mapping_start.anchor)
                    || (event1->data.mapping_start.anchor && event2->data.mapping_start.anchor
                        && strcmp((char *)event1->data.mapping_start.anchor,
                            (char *)event2->data.mapping_start.anchor) != 0))
                return 0;
            if ((event1->data.mapping_start.tag && !event2->data.mapping_start.tag)
                    || (!event1->data.mapping_start.tag && event2->data.mapping_start.tag)
                    || (event1->data.mapping_start.tag && event2->data.mapping_start.tag
                        && strcmp((char *)event1->data.mapping_start.tag,
                            (char *)event2->data.mapping_start.tag) != 0))
                return 0;
            if ((event1->data.mapping_start.implicit != event2->data.mapping_start.implicit)
                    /* || (event2->data.mapping_start.style != event2->data.mapping_start.style) */)
                return 0;
            return 1;

        default:
            return 1;
    }
}

int copy_event(yaml_event_t *event_to, yaml_event_t *event_from)
{
    switch (event_from->type)
    {
        case YAML_STREAM_START_EVENT:
            return yaml_stream_start_event_initialize(event_to,
                    event_from->data.stream_start.encoding);

        case YAML_STREAM_END_EVENT:
            return yaml_stream_end_event_initialize(event_to);

        case YAML_DOCUMENT_START_EVENT:
            return yaml_document_start_event_initialize(event_to,
                    event_from->data.document_start.version_directive,
                    event_from->data.document_start.tag_directives.start,
                    event_from->data.document_start.tag_directives.end,
                    event_from->data.document_start.implicit);

        case YAML_DOCUMENT_END_EVENT:
            return yaml_document_end_event_initialize(event_to,
                    event_from->data.document_end.implicit);

        case YAML_ALIAS_EVENT:
            return yaml_alias_event_initialize(event_to,
                    event_from->data.alias.anchor);

        case YAML_SCALAR_EVENT:
            return yaml_scalar_event_initialize(event_to,
                    event_from->data.scalar.anchor,
                    event_from->data.scalar.tag,
                    event_from->data.scalar.value,
                    event_from->data.scalar.length,
                    event_from->data.scalar.plain_implicit,
                    event_from->data.scalar.quoted_implicit,
                    event_from->data.scalar.style);

        case YAML_SEQUENCE_START_EVENT:
            return yaml_sequence_start_event_initialize(event_to,
                    event_from->data.sequence_start.anchor,
                    event_from->data.sequence_start.tag,
                    event_from->data.sequence_start.implicit,
                    event_from->data.sequence_start.style);

        case YAML_SEQUENCE_END_EVENT:
            return yaml_sequence_end_event_initialize(event_to);

        case YAML_MAPPING_START_EVENT:
            return yaml_mapping_start_event_initialize(event_to,
                    event_from->data.mapping_start.anchor,
                    event_from->data.mapping_start.tag,
                    event_from->data.mapping_start.implicit,
                    event_from->data.mapping_start.style);

        case YAML_MAPPING_END_EVENT:
            return yaml_mapping_end_event_initialize(event_to);
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;

  yaml_parser_t parser;
  yaml_emitter_t emitter;
  yaml_event_t event;
  unsigned char buffer[BUFFER_SIZE+1];
  size_t written = 0;
  yaml_event_t events[MAX_EVENTS];
  size_t event_number = 0;
  bool done = false;
  int count = 0;
  int error = 0;
  bool is_canonical = data[0] & 1;
  bool is_unicode = data[1] & 1;
  data = data + 2;
  size = size - 2;

  if(!yaml_parser_initialize(&parser))
    return 0;

  yaml_parser_set_input_string(&parser, data, size);
  if(!yaml_emitter_initialize(&emitter)) {
    yaml_parser_delete(&parser);
    return 0;
  }

  if (is_canonical) {
      yaml_emitter_set_canonical(&emitter, 1);
  }
  if (is_unicode) {
      yaml_emitter_set_unicode(&emitter, 1);
  }
  yaml_emitter_set_output_string(&emitter, buffer, BUFFER_SIZE, &written);

  while (!done)
  {
      if (!yaml_parser_parse(&parser, &event)) {
          error = 1;
          break;
      }

      done = (event.type == YAML_STREAM_END_EVENT);
      if(!(event_number < MAX_EVENTS)) {
        yaml_event_delete(&event);
        error = 1;
        break;
      }

      if(!(copy_event(&(events[event_number++]), &event))) {
        yaml_event_delete(&event);
        error = 1;
        break;
      }

      if(!(yaml_emitter_emit(&emitter, &event))) {
        error = 1;
        break;
      }

      count ++;
  }

  yaml_parser_delete(&parser);
  yaml_emitter_delete(&emitter);

  if (!error)
  {
      count = done = 0;
      if(!yaml_parser_initialize(&parser))
        return 0;

      yaml_parser_set_input_string(&parser, buffer, written);

      while (!done)
      {
          if(!yaml_parser_parse(&parser, &event))
            break;

          done = (event.type == YAML_STREAM_END_EVENT);
          if(!compare_events(events+count, &event)) {
            yaml_event_delete(&event);
            break;
          }

          yaml_event_delete(&event);
          count ++;
      }
      yaml_parser_delete(&parser);
  }

  for (int k = 0; k < event_number; k ++) {
      yaml_event_delete(events+k);
  }

  return 0;
}
