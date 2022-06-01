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
  yaml_event_t event;

  /* Initialize the parser and emitter objects. */

  if (!yaml_parser_initialize(&parser))
    return 0;

  if (!yaml_emitter_initialize(&emitter))
    goto cleanup_parser;

  /* Set the parser parameters. */

  yaml_parser_set_input_string(&parser, data, size);

  /* Set the emitter parameters. */
  yaml_output_buffer_t out = {/*buf=*/NULL, /*size=*/0};
  yaml_emitter_set_output(&emitter, yaml_write_handler, &out);

  yaml_emitter_set_canonical(&emitter, is_canonical);
  yaml_emitter_set_unicode(&emitter, is_unicode);

  /* The main loop. */

  while (!done) {
    /* Get the next event. */

    if (!yaml_parser_parse(&parser, &event))
      break;

    /* Check if this is the stream end. */

    done = (event.type == YAML_STREAM_END_EVENT);

    /* Emit the event. */

    if (!yaml_emitter_emit(&emitter, &event))
      break;
  }

  free(out.buf);
  yaml_emitter_delete(&emitter);

cleanup_parser:

  yaml_parser_delete(&parser);
  return 0;
}
