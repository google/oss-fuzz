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

#include "src/conf.h"
#include "src/regex_match.h"
#include "src/utils.h"

// Same patterns as IP_ADDRESS_ROUTE and NUMBER_ROUTE in src/http_routes.h.
#define IP_ADDRESS_ROUTE "/ip-addresses/(.+)"
#define NUMBER_ROUTE "/numbers/(\\+?[0-9]+$)"

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sentrypeer_config *config = sentrypeer_config_new();
	if (config == NULL) {
		return 0;
	}

	// The inputs below are NUL-terminated strings, like a URL from libmicrohttpd.
	char *str = malloc(size + 1);
	if (str == NULL) {
		sentrypeer_config_destroy(&config);
		return 0;
	}
	if (size > 0) {
		memcpy(str, data, size);
	}
	str[size] = '\0';

	char *matched = NULL;
	if (regex_match(str, IP_ADDRESS_ROUTE, &matched, config) ==
	    EXIT_SUCCESS) {
		if (matched != NULL) {
			valid_ip_address_format(matched);
		}
		free(matched);
	}

	matched = NULL;
	if (regex_match(str, NUMBER_ROUTE, &matched, config) == EXIT_SUCCESS) {
		free(matched);
	}

	valid_ip_address_format(str);
	is_valid_uuid(str);

	char log_buf[256];
	util_sanitise_for_log(log_buf, str, sizeof(log_buf));

	free(str);
	sentrypeer_config_destroy(&config);
	return 0;
}
