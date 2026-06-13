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
#include "src/igd_desc_parse.h"
#include "src/minixml.h"

/*
 * Fuzz IGD description parser — parses the XML device description returned
 * by UPnP IGD routers. This is fetched over HTTP from the router and is
 * fully attacker-controlled in a network-adjacent threat model.
 */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	struct IGDdatas data;
	struct xmlparser parser;

	char *buf = malloc(insize + 1);
	if (!buf)
		return 0;
	memcpy(buf, in, insize);
	buf[insize] = '\0';

	memset(&data, 0, sizeof(data));
	memset(&parser, 0, sizeof(parser));

	parser.xmlstart = buf;
	parser.xmlsize = (int)insize;
	parser.data = &data;
	parser.starteltfunc = IGDstartelt;
	parser.endeltfunc = IGDendelt;
	parser.datafunc = IGDdata;
	parser.attfunc = NULL;

	parsexml(&parser);

	free(buf);
	return 0;
}
