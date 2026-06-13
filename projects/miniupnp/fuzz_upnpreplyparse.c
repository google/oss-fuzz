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
#include "src/upnpreplyparse.h"

/*
 * Fuzz UPnP SOAP reply parsing.
 * UPnP SOAP responses from IGD routers are attacker-controlled in a
 * network-adjacent threat model — a rogue router can send crafted replies.
 */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	struct NameValueParserData data;

	/* Parser needs null-terminated input */
	char *buf = malloc(insize + 1);
	if (!buf)
		return 0;
	memcpy(buf, in, insize);
	buf[insize] = '\0';

	ParseNameValue(buf, (int)insize, &data);
	ClearNameValueList(&data);

	free(buf);
	return 0;
}
