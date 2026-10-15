// Copyright 2026 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "src/bad_actor.h"
#include "src/conf.h"
#include "src/sip_parser.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sentrypeer_config *config = sentrypeer_config_new();
	if (config == NULL) {
		return 0;
	}

	bad_actor *event = bad_actor_new(0, 0, 0, 0, 0, 0, 0, 0, config->node_id);
	if (event != NULL) {
		// Exact-sized, unterminated copy so ASan catches over-reads.
		char *packet = malloc(size ? size : 1);
		if (packet != NULL) {
			memcpy(packet, data, size);
			sip_message_parser(packet, size, event, config);
			free(packet);
		}
		bad_actor_destroy(&event);
	}

	sentrypeer_config_destroy(&config);
	return 0;
}
