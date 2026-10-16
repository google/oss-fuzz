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
#include "src/json_logger.h"

// json_to_bad_actor() handles JSON received from other peers on the DHT.
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sentrypeer_config *config = sentrypeer_config_new();
	if (config == NULL) {
		return 0;
	}

	char *json = malloc(size + 1);
	if (json == NULL) {
		sentrypeer_config_destroy(&config);
		return 0;
	}
	if (size > 0) {
		memcpy(json, data, size);
	}
	json[size] = '\0';

	bad_actor *event = json_to_bad_actor(config, json);
	if (event != NULL) {
		char *round_trip = bad_actor_to_json(config, event);
		free(round_trip);
		bad_actor_destroy(&event);
	}

	free(json);
	sentrypeer_config_destroy(&config);
	return 0;
}
