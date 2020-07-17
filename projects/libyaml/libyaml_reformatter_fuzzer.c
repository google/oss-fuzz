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

#ifdef NDEBUG
#undef NDEBUG
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return 0;

  int k;
  int done = 0;
  int canonical = data[0] & 1;
  int unicode = data[1] & 1;

  yaml_parser_t parser;
  yaml_emitter_t emitter;
  yaml_event_t event;
  FILE *f;

  /* Clear the objects. */

  memset(&parser, 0, sizeof(parser));
  memset(&emitter, 0, sizeof(emitter));
  memset(&event, 0, sizeof(event));

  /* Initialize the parser and emitter objects. */

  if (!yaml_parser_initialize(&parser))
      goto error;

  if (!yaml_emitter_initialize(&emitter))
      goto error;

  /* Set the parser parameters. */

  yaml_parser_set_input_string(&parser, data, size);

  /* Set the emitter parameters. */

  f = tmpfile();
  if (!f) return 0;
  yaml_emitter_set_output_file(&emitter, f);

  yaml_emitter_set_canonical(&emitter, canonical);
  yaml_emitter_set_unicode(&emitter, unicode);

  /* The main loop. */

  while (!done)
  {
      /* Get the next event. */

      if (!yaml_parser_parse(&parser, &event))
          break;

      /* Check if this is the stream end. */

      if (event.type == YAML_STREAM_END_EVENT) {
          done = 1;
      }

      /* Emit the event. */

      if (!yaml_emitter_emit(&emitter, &event))
          break;
  }

error:
  yaml_parser_delete(&parser);
  yaml_emitter_delete(&emitter);

  return 0;
}
